// Main entry point
#include "sniffer.h"
#include "stats.h"
#include "db.h"
#include "logger.h"
#include "api.h"
#include "security.h"
#include "util.h"
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *prog) {
    printf("Usage: %s [--iface N|NAME] [--filter BPF] [--verbose] [--quiet] [--no-db]\n", prog);
    printf("       [--log-level 0-3] [--snaplen N] [--no-promisc] [--timeout-ms N] [--write "
           "file.pcap]\n");
    printf("       [--read file.pcap] [--api-port PORT] [--api-bind ADDR] [--api-token TOKEN]\n");
    printf("Env: SNIFFER_IFACE, SNIFFER_FILTER, SNIFFER_VERBOSE=1, SNIFFER_SNAPLEN,\n");
    printf("     SNIFFER_PROMISC=0, SNIFFER_TIMEOUT_MS, SNIFFER_WRITE, SNIFFER_READ,\n");
    printf("     SNIFFER_API_PORT, SNIFFER_API_BIND, SNIFFER_API_TOKEN, DATABASE_URL,\n");
    printf("     POSTGRES_CONNINFO, AWS_RDS_CONNINFO, LOG_LEVEL=0-3\n");
    printf("       [--state-dir DIR] [--no-env] [--db-required]\n");
    printf("Note: --read (offline replay, no capture privileges needed) conflicts with --write.\n");
}

static void set_env(const char *k, const char *v) {
#ifdef _WIN32
    if (_putenv_s(k, v)) {
        fprintf(stderr, "Cannot set configuration %s\n", k);
        exit(1);
    }
#else
    setenv(k, v, 1);
#endif
}

// Minimal .env loader (KEY=VALUE per line, # comments), from remote work
static int load_env_file(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp)
        return errno == ENOENT ? 0 : -1;
    char line[2048];
    int n = 0;
    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        if (len == sizeof(line) - 1 && line[len - 1] != '\n') {
            int next = fgetc(fp);
            if (next != EOF) {
                fclose(fp);
                return -1;
            }
        }
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';
        char *s = line;
        while (*s && isspace((unsigned char)*s))
            s++;
        if (*s == '\0' || *s == '#')
            continue;
        char *eq = strchr(s, '=');
        if (!eq) {
            fclose(fp);
            return -1;
        }
        *eq = '\0';
        char *key = s, *val = eq + 1;
        while (*key && isspace((unsigned char)*key))
            key++;
        char *ke = key + strlen(key);
        while (ke > key && isspace((unsigned char)ke[-1]))
            *--ke = '\0';
        while (*val && isspace((unsigned char)*val))
            val++;
        char *ve = val + strlen(val);
        while (ve > val && isspace((unsigned char)ve[-1]))
            *--ve = '\0';

        // Handle quoted values: "value" or 'value', with escape support
        if (ve - val >= 2 &&
            ((*val == '"' && *(ve - 1) == '"') || (*val == '\'' && *(ve - 1) == '\''))) {
            val++;
            ve--;
            // Unescape: handle \" \' \\ and \n \t \r
            char *dst = val;
            for (char *src = val; src < ve; src++) {
                if (*src == '\\' && src + 1 < ve) {
                    src++;
                    switch (*src) {
                    case 'n':
                        *dst++ = '\n';
                        break;
                    case 't':
                        *dst++ = '\t';
                        break;
                    case 'r':
                        *dst++ = '\r';
                        break;
                    case '"':
                        *dst++ = '"';
                        break;
                    case '\'':
                        *dst++ = '\'';
                        break;
                    case '\\':
                        *dst++ = '\\';
                        break;
                    default:
                        *dst++ = *src;
                        break;
                    }
                } else {
                    *dst++ = *src;
                }
            }
            ve = dst;
        }
        *ve = '\0';

        if (*key == '\0')
            continue;
        // Don't override real environment
        if (getenv(key))
            continue;
        set_env(key, val);
        n++;
    }
    int error = ferror(fp);
    fclose(fp);
    if (n > 0)
        printf("[+] Loaded %d vars from %s\n", n, path);
    return error ? -1 : 0;
}

static const char *get_postgres_conninfo(void) {
    // AWS RDS first (remote convention), then generic vars
    const char *c = getenv("AWS_RDS_CONNINFO");
    if (c && c[0]) {
        printf("[+] Using AWS_RDS_CONNINFO\n");
        return c;
    }
    c = getenv("DATABASE_URL");
    if (c && c[0])
        return c;
    c = getenv("POSTGRES_CONNINFO");
    if (c && c[0])
        return c;
    if (getenv("PGHOST"))
        return "service-context";
    return NULL;
}

int main(int argc, char **argv) {
    printf("=== Packet Sniffer + Protocol Analyzer ===\n");
    log_init();
    int no_env = 0;
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "--no-env"))
            no_env = 1;
    if (!no_env && load_env_file(".env")) {
        fprintf(stderr, "Invalid or unreadable .env\n");
        return 1;
    }
    const char *initial_level = getenv("LOG_LEVEL");
    long level;
    if (initial_level && parse_integer(initial_level, 0, 3, &level)) {
        fprintf(stderr, "Invalid LOG_LEVEL\n");
        return 1;
    }
    if (initial_level)
        current_log_level_int = (int)level;

    int no_db = 0, db_required = 0;
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
        } else if (strcmp(argv[i], "--no-env") == 0) {
            continue;
        } else if (strcmp(argv[i], "--db-required") == 0) {
            db_required = 1;
        } else if (strcmp(argv[i], "--state-dir") == 0 && i + 1 < argc) {
            set_env("SNIFFER_STATE_DIR", argv[++i]);
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
            long lv;
            if (parse_integer(argv[++i], 0, 3, &lv)) {
                fprintf(stderr, "Invalid log level\n");
                return 1;
            }
            current_log_level_int = (int)lv;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            return 1;
        }
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
    if (no_db)
        conninfo = NULL;
    if (conninfo && !strcmp(conninfo, "service-context"))
        conninfo = " ";
    if (!conninfo)
        printf("[*] No Postgres conninfo; JSON-only mode (set DATABASE_URL/AWS_RDS_CONNINFO or use "
               "--no-db).\n");

    long value;
    const char *numeric[] = {"SNIFFER_SNAPLEN",        "SNIFFER_TIMEOUT_MS",
                             "SNIFFER_API_PORT",       "STATS_FLUSH_MS",
                             "SNIFFER_QUEUE_BYTES",    "SNIFFER_SYN_THRESHOLD",
                             "SNIFFER_DHCP_THRESHOLD", "SNIFFER_RETENTION_DAYS"};
    const long minima[] = {68, 10, 0, 1000, 262144, 2, 2, 0},
               maxima[] = {262144, 60000, 65535, 3600000, 1073741824, 64, 128, 36500};
    for (unsigned i = 0; i < sizeof(numeric) / sizeof(numeric[0]); i++) {
        const char *v = getenv(numeric[i]);
        if (v && parse_integer(v, minima[i], maxima[i], &value)) {
            fprintf(stderr, "Invalid %s\n", numeric[i]);
            return 1;
        }
    }
    if (db_required && (!conninfo || no_db)) {
        fprintf(stderr, "--db-required needs a connection string\n");
        return 1;
    }
    if (sniffer_init()) {
        fprintf(stderr, "Capture initialization failed\n");
        return 1;
    }
    if (stats_init(conninfo)) {
        fprintf(stderr, "State/persistence initialization failed\n");
        sniffer_cleanup();
        return 1;
    }
    security_init();
    if (db_required) {
        uint64_t end = monotonic_ms() + 5000;
        while (!stats_db_healthy() && monotonic_ms() < end)
            sleep_ms(10);
        if (!stats_db_healthy()) {
            fprintf(stderr, "Required database unavailable\n");
            stats_cleanup();
            security_cleanup();
            sniffer_cleanup();
            return 1;
        }
    }
    if (api_start()) {
        fprintf(stderr, "API startup failed\n");
        stats_cleanup();
        security_cleanup();
        sniffer_cleanup();
        return 1;
    }
    int rc = start_sniffer();
    api_stop();
    if (db_required && !stats_db_healthy())
        rc = 1;
    if (stats_cleanup())
        rc = 1;
    security_cleanup();
    sniffer_cleanup();
    log_cleanup();
    return rc;
}
