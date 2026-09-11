// Main entry point
#include "sniffer.h"
#include "stats.h"
#include "db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *prog) {
    printf("Usage: %s [--iface N|NAME] [--filter BPF] [--verbose] [--no-db]\n", prog);
    printf("Env: SNIFFER_IFACE, SNIFFER_FILTER, SNIFFER_VERBOSE=1, DATABASE_URL\n");
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

int main(int argc, char **argv) {
    printf("=== Packet Sniffer + Protocol Analyzer ===\n");

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
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    const char *conninfo = getenv("DATABASE_URL");
    if (!conninfo) conninfo = getenv("POSTGRES_CONNINFO");
    if (no_db) conninfo = NULL;

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
