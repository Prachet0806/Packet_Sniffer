// Main entry point
#include "sniffer.h"
#include "stats.h"
#include "db.h"
#include "logger.h"
#include "api.h"
#include "security.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *prog) {
    printf("Usage: %s [--iface N|NAME] [--filter BPF] [--verbose] [--quiet] [--no-db]\n", prog);
    printf("       [--log-level 0-3] [--snaplen N] [--no-promisc] [--timeout-ms N] [--write file.pcap]\n");
    printf("       [--read file.pcap] [--api-port PORT] [--api-bind ADDR] [--api-token TOKEN]\n");
    printf("Env: SNIFFER_IFACE, SNIFFER_FILTER, SNIFFER_VERBOSE=1, SNIFFER_SNAPLEN,\n");
    printf("     SNIFFER_PROMISC=0, SNIFFER_TIMEOUT_MS, SNIFFER_WRITE, SNIFFER_READ,\n");
    printf("     SNIFFER_API_PORT, SNIFFER_API_BIND, SNIFFER_API_TOKEN, DATABASE_URL,\n");
    printf("     POSTGRES_CONNINFO, AWS_RDS_CONNINFO, LOG_LEVEL=0-3\n");
    printf("Note: --read (offline replay, no capture privileges needed) conflicts with --write.\n");
}

static void set_env(const char *k, const char *v) {
#ifdef _WIN32
    char buf[1024];
    snprintf(buf, sizeof(buf), "%s=%s", k, v);
    _putenv(buf);
#else
    setenv(k, v, 1);
#endif
}

// Minimal .env loader (KEY=VALUE per line, # comments), from remote work
static void load_env_file(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return;
    char line[2048];
    int n = 0;
    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
        char *s = line;
        while (*s && isspace((unsigned char)*s)) s++;
        if (*s == '\0' || *s == '#') continue;
        char *eq = strchr(s, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = s, *val = eq + 1;
        while (*key && isspace((unsigned char)*key)) key++;
        char *ke = key + strlen(key);
        while (ke > key && isspace((unsigned char)ke[-1])) *--ke = '\0';
        while (*val && isspace((unsigned char)*val)) val++;
        char *ve = val + strlen(val);
        while (ve > val && isspace((unsigned char)ve[-1])) *--ve = '\0';
        
        // Handle quoted values: "value" or 'value', with escape support
        if ((*val == '"' && *(ve-1) == '"') || (*val == '\'' && *(ve-1) == '\'')) {
            val++;
            ve--;
            // Unescape: handle \" \' \\ and \n \t \r
            char *dst = val;
            for (char *src = val; src < ve; src++) {
                if (*src == '\\' && src + 1 < ve) {
                    src++;
                    switch (*src) {
                        case 'n': *dst++ = '\n'; break;
                        case 't': *dst++ = '\t'; break;
                        case 'r': *dst++ = '\r'; break;
                        case '"': *dst++ = '"'; break;
                        case '\'': *dst++ = '\''; break;
                        case '\\': *dst++ = '\\'; break;
                        default: *dst++ = *src; break;
                    }
                } else {
                    *dst++ = *src;
                }
            }
            ve = dst;
        }
        *ve = '\0';
        
        if (*key == '\0') continue;
        // Don't override real environment
        if (getenv(key)) continue;
        set_env(key, val);
        n++;
    }
    fclose(fp);
    if (n > 0) printf("[+] Loaded %d vars from %s\n", n, path);
}

static const char *get_postgres_conninfo(void) {
    // AWS RDS first (remote convention), then generic vars
    const char *c = getenv("AWS_RDS_CONNINFO");
    if (c && c[0]) { printf("[+] Using AWS_RDS_CONNINFO\n"); return c; }
    c = getenv("DATABASE_URL");
    if (c && c[0]) return c;
    c = getenv("POSTGRES_CONNINFO");
    if (c && c[0]) return c;
    return NULL;
}

int main(int argc, char **argv) {
    printf("=== Packet Sniffer + Protocol Analyzer ===\n");
    log_init();
    load_env_file(".env");

    int no_db = 0;
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "--iface") == 0) && i + 1 < argc) {
            set_env("SNIFFER_IFACE", argv[++i]);
        } else if ((strcmp(argv[i], "--filter") == 0) && i + 1 < argc) {
            set_env("SNIFFER_FILTER", argv[++i]);
        } else if (strcmp(argv[i], "--verbose") == 0) {
            set_env("SNIFFER_VERBOSE", "1");
        } else if (strcmp(argv[i], "--quiet") == 0) {
            current_log_level_int = LOG_ERROR;
            set_env("SNIFFER_QUIET", "1");
        } else if (strcmp(argv[i], "--no-db") == 0) {
            no_db = 1;
        } else if ((strcmp(argv[i], "--snaplen") == 0) && i + 1 < argc) {
            set_env("SNIFFER_SNAPLEN", argv[++i]);
        } else if (strcmp(argv[i], "--no-promisc") == 0) {
            set_env("SNIFFER_PROMISC", "0");
        } else if ((strcmp(argv[i], "--timeout-ms") == 0) && i + 1 < argc) {
            set_env("SNIFFER_TIMEOUT_MS", argv[++i]);
        } else if ((strcmp(argv[i], "--write") == 0) && i + 1 < argc) {
            set_env("SNIFFER_WRITE", argv[++i]);
        } else if ((strcmp(argv[i], "--read") == 0) && i + 1 < argc) {
            set_env("SNIFFER_READ", argv[++i]);
        } else if ((strcmp(argv[i], "--api-port") == 0) && i + 1 < argc) {
            set_env("SNIFFER_API_PORT", argv[++i]);
        } else if ((strcmp(argv[i], "--api-bind") == 0) && i + 1 < argc) {
            set_env("SNIFFER_API_BIND", argv[++i]);
        } else if ((strcmp(argv[i], "--api-token") == 0) && i + 1 < argc) {
            set_env("SNIFFER_API_TOKEN", argv[++i]);
        } else if ((strcmp(argv[i], "--log-level") == 0) && i + 1 < argc) {
            int lv = atoi(argv[++i]);
            if (lv < 0) lv = 0;
            if (lv > 3) lv = 3;
            current_log_level_int = lv;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    const char *ll = getenv("LOG_LEVEL");
    if (ll) {
        int lv = atoi(ll);
        if (lv >= 0 && lv <= 3) current_log_level_int = lv;
    }

    // --read (offline replay) conflicts with --write (live record)
    {
        const char *rp = getenv("SNIFFER_READ");
        const char *wp = getenv("SNIFFER_WRITE");
        if (rp && rp[0] && wp && wp[0]) {
            fprintf(stderr, "Error: --read and --write are mutually exclusive.\n");
            usage(argv[0]);
            return 1;
        }
    }

    const char *conninfo = get_postgres_conninfo();
    if (no_db) conninfo = NULL;
    if (!conninfo)
        printf("[*] No Postgres conninfo; JSON-only mode (set DATABASE_URL/AWS_RDS_CONNINFO or use --no-db).\n");

    stats_init(conninfo);
    security_init();
    if (api_start() != 0) {
        fprintf(stderr, "API failed to start (check SNIFFER_API_*).\n");
        stats_cleanup();
        db_disconnect();
        return 1;
    }
    if (conninfo && conninfo[0]) {
        // db.c layer kept for direct queries; connect best-effort
        if (db_connect(conninfo) == 0) {
            db_ensure_schema();
        }
    }

    start_sniffer();

    // Flush on exit (Ctrl+C path also reaches here after pcap_breakloop)
    api_stop();
    stats_save_json("stats.json");
    if (!no_db) stats_save_postgres(NULL);
    stats_cleanup();
    db_disconnect();
    return 0;
}
