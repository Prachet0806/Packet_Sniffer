// stats.c - Performance-optimized version
#include "stats.h"
#include <stdio.h>
#include <windows.h>
#include <libpq-fe.h>
#include <string.h>

#define BATCH_INTERVAL_MS 15000  // Flush every 15 seconds
#define MAX_RETRY_ATTEMPTS 3
#define INITIAL_RETRY_DELAY_MS 1000
#define JSON_FILE "stats.json"

ProtocolStats stats;
static HANDLE batch_thread_handle = NULL;
static HANDLE shutdown_event = NULL;  // Event for graceful thread termination
static char postgres_conninfo[512] = {0};
static PGconn *pg_conn = NULL;  // Persistent DB connection
static int db_enabled = 1;  // Track if database is available
// Return codes for stats_save_postgres
#define STATS_DB_OK 0
#define STATS_DB_CONN_FAIL -2
#define STATS_DB_QUERY_FAIL -3

// Forward declaration
static DWORD WINAPI stats_batch_thread(LPVOID lpParam);

// Try to (re)establish a Postgres connection with simple retries
static PGconn* connect_with_retry(const char *conninfo) {
    PGconn *conn = NULL;
    int retry_count = 0;
    int delay_ms = INITIAL_RETRY_DELAY_MS;

    while (retry_count < MAX_RETRY_ATTEMPTS) {
        conn = PQconnectdb(conninfo);
        if (conn && PQstatus(conn) == CONNECTION_OK) {
            return conn;
        }

        if (conn) {
            const char *msg = PQerrorMessage(conn);
            printf("[!] Postgres connection attempt %d error: %s\n",
                   retry_count + 1, msg ? msg : "(no message)");
        } else {
            printf("[!] Postgres connection attempt %d error: could not allocate connection\n",
                   retry_count + 1);
        }

        if (conn) {
            PQfinish(conn);
            conn = NULL;
        }

        retry_count++;
        if (retry_count < MAX_RETRY_ATTEMPTS) {
            printf("[!] Postgres connection attempt %d failed, retrying in %d ms\n",
                   retry_count, delay_ms);
            Sleep(delay_ms);
            delay_ms *= 2;  // exponential backoff
        }
    }

    printf("[!] Postgres connection failed after %d attempts\n", MAX_RETRY_ATTEMPTS);
    return NULL;
}

// Ensure we have a healthy connection before issuing commands
static int ensure_pg_connection(void) {
    if (postgres_conninfo[0] == '\0') {
        printf("[!] Postgres connection string is empty; skipping DB writes\n");
        return -1;  // connection disabled
    }

    if (pg_conn && PQstatus(pg_conn) == CONNECTION_OK) {
        return 0;
    }

    if (pg_conn) {
        PQfinish(pg_conn);
        pg_conn = NULL;
    }

    pg_conn = connect_with_retry(postgres_conninfo);
    if (!pg_conn) {
        printf("[!] Failed to establish Postgres connection\n");
        return -1;
    }

    printf("[+] Postgres connection established\n");
    return 0;
}

// Initialize stats and start batch thread
void stats_init(const char *conninfo) {
    memset(&stats, 0, sizeof(stats));
    if (conninfo) {
        strncpy(postgres_conninfo, conninfo, sizeof(postgres_conninfo) - 1);
        postgres_conninfo[sizeof(postgres_conninfo) - 1] = '\0';  // Ensure null termination
    }

    // Load previous stats from JSON if exists
    stats_load_json(JSON_FILE);

    // Connect to Postgres once
    if (postgres_conninfo[0] != '\0') {
        if (ensure_pg_connection() != 0) {
            printf("[!] Postgres connection failed during init - using file-only mode\n");
            db_enabled = 0;
        } else {
            db_enabled = 1;
        }
    } else {
        db_enabled = 0;
    }

    // Create shutdown event for graceful thread termination
    shutdown_event = CreateEvent(NULL, TRUE, FALSE, NULL);  // Manual-reset event
    if (!shutdown_event) {
        fprintf(stderr, "[!] Failed to create shutdown event\n");
        return;
    }

    // Start batch thread
    batch_thread_handle = CreateThread(NULL, 0, stats_batch_thread, NULL, 0, NULL);
    if (!batch_thread_handle) {
        fprintf(stderr, "[!] Failed to create stats batch thread\n");
        CloseHandle(shutdown_event);
        shutdown_event = NULL;
    }
}

// Cleanup
void stats_cleanup(void) {
    // Signal batch thread to stop
    if (shutdown_event) {
        SetEvent(shutdown_event);  // Signal shutdown
        
        // Wait for thread to finish (with timeout)
        if (batch_thread_handle) {
            DWORD wait_result = WaitForSingleObject(batch_thread_handle, 10000);  // 10 second timeout
            if (wait_result == WAIT_TIMEOUT) {
                fprintf(stderr, "[!] Stats batch thread did not terminate in time\n");
                fprintf(stderr, "[!] Skipping final database save to avoid corruption\n");
                // Don't call TerminateThread - too dangerous with locks
            } else {
                // Thread exited cleanly - safe to do final save
                if (db_enabled) {
                    stats_save_postgres(postgres_conninfo);
                }
                stats_save_json(JSON_FILE);
            }
            CloseHandle(batch_thread_handle);
            batch_thread_handle = NULL;
        }
        
        CloseHandle(shutdown_event);
        shutdown_event = NULL;
    }
    
    // Close PostgreSQL connection
    if (pg_conn) {
        PQfinish(pg_conn);
        pg_conn = NULL;
    }
}

// Increment protocol stats using 64-bit atomic operations
void stats_increment(const char *proto) {
    InterlockedIncrement64((volatile LONG64*)&stats.total_packets);
    if (strcmp(proto, "ETH") == 0) InterlockedIncrement64((volatile LONG64*)&stats.ethernet);
    else if (strcmp(proto, "IPv4") == 0) InterlockedIncrement64((volatile LONG64*)&stats.ipv4);
    else if (strcmp(proto, "IPv6") == 0) InterlockedIncrement64((volatile LONG64*)&stats.ipv6);
    else if (strcmp(proto, "TCP") == 0) InterlockedIncrement64((volatile LONG64*)&stats.tcp);
    else if (strcmp(proto, "UDP") == 0) InterlockedIncrement64((volatile LONG64*)&stats.udp);
    else if (strcmp(proto, "ICMP") == 0) InterlockedIncrement64((volatile LONG64*)&stats.icmp);
    else if (strcmp(proto, "ARP") == 0) InterlockedIncrement64((volatile LONG64*)&stats.arp);
    else if (strcmp(proto, "DNS") == 0) InterlockedIncrement64((volatile LONG64*)&stats.dns);
    else if (strcmp(proto, "HTTP") == 0) InterlockedIncrement64((volatile LONG64*)&stats.http);
    else if (strcmp(proto, "HTTPS") == 0) InterlockedIncrement64((volatile LONG64*)&stats.https);
    else if (strcmp(proto, "DHCP") == 0) InterlockedIncrement64((volatile LONG64*)&stats.dhcp);
}

// Save stats to JSON with error checking
int stats_save_json(const char *filename) {
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        fprintf(stderr, "[!] Failed to open %s for writing\n", filename);
        return -1;
    }

    int result = fprintf(fp,
        "{\n"
        "  \"total_packets\": %llu,\n"
        "  \"ethernet\": %llu,\n"
        "  \"ipv4\": %llu,\n"
        "  \"ipv6\": %llu,\n"
        "  \"tcp\": %llu,\n"
        "  \"udp\": %llu,\n"
        "  \"icmp\": %llu,\n"
        "  \"arp\": %llu,\n"
        "  \"dns\": %llu,\n"
        "  \"http\": %llu,\n"
        "  \"https\": %llu,\n"
        "  \"dhcp\": %llu\n"
        "}\n",
        (unsigned long long)stats.total_packets,
        (unsigned long long)stats.ethernet,
        (unsigned long long)stats.ipv4,
        (unsigned long long)stats.ipv6,
        (unsigned long long)stats.tcp,
        (unsigned long long)stats.udp,
        (unsigned long long)stats.icmp,
        (unsigned long long)stats.arp,
        (unsigned long long)stats.dns,
        (unsigned long long)stats.http,
        (unsigned long long)stats.https,
        (unsigned long long)stats.dhcp
    );

    if (result < 0) {
        fprintf(stderr, "[!] Failed to write to %s\n", filename);
        fclose(fp);
        return -1;
    }

    if (fclose(fp) != 0) {
        fprintf(stderr, "[!] Failed to close %s\n", filename);
        return -1;
    }

    return 0;
}

// Load stats from JSON (improved parsing with better error handling)
int stats_load_json(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) return -1;

    char line[256];
    char key[64];
    unsigned long long value;
    int found_count = 0;
    
    // Read file line by line for more robust parsing
    while (fgets(line, sizeof(line), fp)) {
        // Skip empty lines and comments
        if (line[0] == '\n' || line[0] == '\r' || line[0] == '\0') continue;
        
        // Try to parse "key": value pattern
        // Handle both with and without whitespace: "key":value or "key" : value
        if (sscanf(line, " \"%63[^\"]\" : %llu", key, &value) == 2 ||
            sscanf(line, " \"%63[^\"]\": %llu", key, &value) == 2 ||
            sscanf(line, "\"%63[^\"]\" : %llu", key, &value) == 2 ||
            sscanf(line, "\"%63[^\"]\": %llu", key, &value) == 2) {
            
            // Remove trailing comma if present
            size_t key_len = strlen(key);
            if (key_len > 0 && key[key_len - 1] == ',') {
                key[key_len - 1] = '\0';
            }
            
            if (strcmp(key, "total_packets") == 0) {
                stats.total_packets = value;
                found_count++;
            } else if (strcmp(key, "ethernet") == 0) {
                stats.ethernet = value;
                found_count++;
            } else if (strcmp(key, "ipv4") == 0) {
                stats.ipv4 = value;
                found_count++;
            } else if (strcmp(key, "ipv6") == 0) {
                stats.ipv6 = value;
                found_count++;
            } else if (strcmp(key, "tcp") == 0) {
                stats.tcp = value;
                found_count++;
            } else if (strcmp(key, "udp") == 0) {
                stats.udp = value;
                found_count++;
            } else if (strcmp(key, "icmp") == 0) {
                stats.icmp = value;
                found_count++;
            } else if (strcmp(key, "arp") == 0) {
                stats.arp = value;
                found_count++;
            } else if (strcmp(key, "dns") == 0) {
                stats.dns = value;
                found_count++;
            } else if (strcmp(key, "http") == 0) {
                stats.http = value;
                found_count++;
            } else if (strcmp(key, "https") == 0) {
                stats.https = value;
                found_count++;
            } else if (strcmp(key, "dhcp") == 0) {
                stats.dhcp = value;
                found_count++;
            }
        }
    }

    fclose(fp);
    
    if (found_count > 0) {
        printf("[+] Loaded %d stats from %s\n", found_count, filename);
    }
    
    return 0;
}

// Save stats to Postgres using persistent connection
int stats_save_postgres(const char *conninfo) {
    (void)conninfo; // ignored, using persistent pg_conn
    
    // Skip if database is disabled
    if (!db_enabled) {
        return STATS_DB_OK;
    }
    
    if (ensure_pg_connection() != 0) {
        db_enabled = 0;  // Disable for future attempts
        return STATS_DB_CONN_FAIL;
    }

    // Prepare parameter strings
    char buf_total[32], buf_eth[32], buf_ipv4[32], buf_ipv6[32], buf_tcp[32], buf_udp[32],
         buf_icmp[32], buf_arp[32], buf_dns[32], buf_http[32], buf_https[32], buf_dhcp[32];

    snprintf(buf_total, sizeof(buf_total), "%llu", (unsigned long long)stats.total_packets);
    snprintf(buf_eth, sizeof(buf_eth), "%llu", (unsigned long long)stats.ethernet);
    snprintf(buf_ipv4, sizeof(buf_ipv4), "%llu", (unsigned long long)stats.ipv4);
    snprintf(buf_ipv6, sizeof(buf_ipv6), "%llu", (unsigned long long)stats.ipv6);
    snprintf(buf_tcp, sizeof(buf_tcp), "%llu", (unsigned long long)stats.tcp);
    snprintf(buf_udp, sizeof(buf_udp), "%llu", (unsigned long long)stats.udp);
    snprintf(buf_icmp, sizeof(buf_icmp), "%llu", (unsigned long long)stats.icmp);
    snprintf(buf_arp, sizeof(buf_arp), "%llu", (unsigned long long)stats.arp);
    snprintf(buf_dns, sizeof(buf_dns), "%llu", (unsigned long long)stats.dns);
    snprintf(buf_http, sizeof(buf_http), "%llu", (unsigned long long)stats.http);
    snprintf(buf_https, sizeof(buf_https), "%llu", (unsigned long long)stats.https);
    snprintf(buf_dhcp, sizeof(buf_dhcp), "%llu", (unsigned long long)stats.dhcp);

    const char *paramValues[12] = {
        buf_total, buf_eth, buf_ipv4, buf_ipv6, buf_tcp, buf_udp,
        buf_icmp, buf_arp, buf_dns, buf_http, buf_https, buf_dhcp
    };

    const char *query =
        "INSERT INTO protocol_stats(total_packets, ethernet, ipv4, ipv6, tcp, udp, icmp, arp, dns, http, https, dhcp) "
        "VALUES ($1::bigint,$2::bigint,$3::bigint,$4::bigint,$5::bigint,$6::bigint,$7::bigint,$8::bigint,$9::bigint,$10::bigint,$11::bigint,$12::bigint);";

    PGresult *res = PQexecParams(
        pg_conn,
        query,
        12,           // number of params
        NULL,         // param types
        paramValues,  // values
        NULL,         // lengths
        NULL,         // formats
        0             // result text format
    );

    if (res == NULL) {
        fprintf(stderr, "[!] PQexecParams returned NULL: %s\n", PQerrorMessage(pg_conn));
        // Force reconnect next time
        PQfinish(pg_conn);
        pg_conn = NULL;
        return STATS_DB_QUERY_FAIL;
    }

    ExecStatusType st = PQresultStatus(res);
    if (st != PGRES_COMMAND_OK) {
        fprintf(stderr, "[!] Postgres insert failed: %s\n", PQerrorMessage(pg_conn));
        PQclear(res);
        // Force reconnect next time
        PQfinish(pg_conn);
        pg_conn = NULL;
        return STATS_DB_QUERY_FAIL;
    }

    PQclear(res);
    return STATS_DB_OK;
}

// Batch thread for periodic flush using event-based shutdown
static DWORD WINAPI stats_batch_thread(LPVOID lpParam) {
    (void)lpParam;
    
    while (1) {
        // Wait for shutdown event or timeout
        DWORD wait_result = WaitForSingleObject(shutdown_event, BATCH_INTERVAL_MS);
        
        if (wait_result == WAIT_OBJECT_0) {
            // Shutdown event signaled
            break;
        }
        
        // Timeout - perform periodic save
        if (db_enabled) {
            stats_save_postgres(postgres_conninfo);
        }
        stats_save_json(JSON_FILE);
    }
    
    return 0;
}
