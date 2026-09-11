// Main entry point
#include "sniffer.h"
#include "stats.h"
#include "db.h"
#include "logger.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *prog) {
    printf("Usage: %s [--iface N|NAME] [--filter BPF] [--verbose] [--no-db] [--log-level 0-3]\n", prog);
    printf("Env: SNIFFER_IFACE, SNIFFER_FILTER, SNIFFER_VERBOSE=1, DATABASE_URL,\n");
    printf("     POSTGRES_CONNINFO, AWS_RDS_CONNINFO, LOG_LEVEL=0-3\n");
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
    load_env_file(".env");

    int no_db = 0;
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "--iface") == 0) && i + 1 < argc) {
            set_env("SNIFFER_IFACE", argv[++i]);
        } else if ((strcmp(argv[i], "--filter") == 0) && i + 1 < argc) {
            set_env("SNIFFER_FILTER", argv[++i]);
        } else if (strcmp(argv[i], "--verbose") == 0) {
            set_env("SNIFFER_VERBOSE", "1");
        } else if (strcmp(argv[i], "--no-db") == 0) {
            no_db = 1;
        } else if ((strcmp(argv[i], "--log-level") == 0) && i + 1 < argc) {
            int lv = atoi(argv[++i]);
            if (lv < 0) lv = 0;
            if (lv > 3) lv = 3;
            current_log_level = (LogLevel)lv;
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
        if (lv >= 0 && lv <= 3) current_log_level = (LogLevel)lv;
    }

    const char *conninfo = get_postgres_conninfo();
    if (no_db) conninfo = NULL;
    if (!conninfo)
        printf("[*] No Postgres conninfo; JSON-only mode (set DATABASE_URL/AWS_RDS_CONNINFO or use --no-db).\n");

    stats_init(conninfo);
    if (conninfo && conninfo[0]) {
        // db.c layer kept for direct queries; connect best-effort
        if (db_connect(conninfo) == 0) {
            db_ensure_schema();
        }
    }

    start_sniffer();

    // Flush on exit (Ctrl+C path also reaches here after pcap_breakloop)
    stats_save_json("stats.json");
    if (!no_db) stats_save_postgres(NULL);
    stats_cleanup();
    db_disconnect();
    return 0;
}
