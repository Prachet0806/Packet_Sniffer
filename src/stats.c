// stats.c - Statistics implementation (thread-safe, no lock-held I/O)
#include "stats.h"
#include "os_compat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#ifdef HAVE_LIBPQ
#include <libpq-fe.h>
#endif

#ifndef DEFAULT_BATCH_MS
#define DEFAULT_BATCH_MS 60000
#endif
#define JSON_FILE "stats.json"

// Global objects (kept for header compat)
ProtocolStats stats;
#ifdef _WIN32
CRITICAL_SECTION stats_cs;
#else
pthread_mutex_t stats_cs;
#endif

#ifdef _WIN32
static HANDLE batch_thread_handle = NULL;
static HANDLE batch_stop_event = NULL;
#else
static pthread_t batch_thread_handle;
static int batch_thread_started = 0;
static volatile int batch_stop = 0;
#endif
static char postgres_conninfo[1024] = {0};
#ifdef HAVE_LIBPQ
static PGconn *pg_conn = NULL;
#endif
static int batch_ms = DEFAULT_BATCH_MS;

static void lock_init(void) {
#ifdef _WIN32
    InitializeCriticalSection(&stats_cs);
#else
    pthread_mutex_init(&stats_cs, NULL);
#endif
}
static void lock_destroy(void) {
#ifdef _WIN32
    DeleteCriticalSection(&stats_cs);
#else
    pthread_mutex_destroy(&stats_cs);
#endif
}
static void lock(void) {
#ifdef _WIN32
    EnterCriticalSection(&stats_cs);
#else
    pthread_mutex_lock(&stats_cs);
#endif
}
static void unlock(void) {
#ifdef _WIN32
    LeaveCriticalSection(&stats_cs);
#else
    pthread_mutex_unlock(&stats_cs);
#endif
}

#ifdef HAVE_LIBPQ
static int pg_connect(void) {
    if (!postgres_conninfo[0] || pg_conn) return 0;
    pg_conn = PQconnectdb(postgres_conninfo);
    if (PQstatus(pg_conn) != CONNECTION_OK) {
        printf("[!] PostgreSQL connection failed: %s\n", PQerrorMessage(pg_conn));
        PQfinish(pg_conn);
        pg_conn = NULL;
        return -1;
    }
    // Ensure schema exists
    const char *ddl =
        "CREATE TABLE IF NOT EXISTS protocol_stats("
        "id SERIAL PRIMARY KEY, interval_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
        "total_packets BIGINT, total_bytes BIGINT,"
        "ethernet BIGINT, ethernet_bytes BIGINT, ipv4 BIGINT, ipv4_bytes BIGINT,"
        "ipv6 BIGINT, ipv6_bytes BIGINT, tcp BIGINT, tcp_bytes BIGINT,"
        "udp BIGINT, udp_bytes BIGINT, icmp BIGINT, icmp_bytes BIGINT,"
        "arp BIGINT, arp_bytes BIGINT, dns BIGINT, dns_bytes BIGINT,"
        "http BIGINT, http_bytes BIGINT, https BIGINT, https_bytes BIGINT,"
        "dhcp BIGINT, dhcp_bytes BIGINT);"
        "CREATE TABLE IF NOT EXISTS alerts("
        "id SERIAL PRIMARY KEY, time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
        "type VARCHAR(32), src VARCHAR(64), dst VARCHAR(64), detail TEXT);";
    PGresult *r = PQexec(pg_conn, ddl);
    if (PQresultStatus(r) != PGRES_COMMAND_OK) {
        printf("[!] stats schema ensure failed: %s\n", PQerrorMessage(pg_conn));
        PQclear(r);
        return -1;
    }
    PQclear(r);
    return 0;
}
#else
static int pg_connect(void) { return -1; }
#endif

// ---------------------- Initialization ----------------------
void stats_init(const char *conninfo) {
    lock_init();
    lock(); memset(&stats, 0, sizeof(stats)); unlock();

    if (conninfo) {
        strncpy(postgres_conninfo, conninfo, sizeof(postgres_conninfo)-1);
        postgres_conninfo[sizeof(postgres_conninfo)-1] = '\0';
    } else postgres_conninfo[0] = '\0';

    const char *env_ms = getenv("STATS_FLUSH_MS");
    if (env_ms) { long v = atol(env_ms); if (v >= 1000 && v <= 3600000) batch_ms = (int)v; }

    stats_load_json(JSON_FILE);

#ifdef HAVE_LIBPQ
    if (postgres_conninfo[0]) {
        if (pg_connect() != 0) {
            printf("[stats] PostgreSQL connection failed; continuing in JSON-only mode.\n");
        }
    } else printf("[stats] No DATABASE_URL; PostgreSQL disabled (JSON only).\n");
#else
    if (postgres_conninfo[0])
        printf("[stats] Built without libpq; PostgreSQL disabled (JSON only).\n");
#endif

#ifdef _WIN32
    batch_stop_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    batch_thread_handle = CreateThread(NULL, 0, stats_batch_thread, NULL, 0, NULL);
    if (!batch_thread_handle) fprintf(stderr, "[stats] batch thread create failed\n");
#else
    batch_stop = 0;
    if (pthread_create(&batch_thread_handle, NULL, stats_batch_thread, NULL) == 0)
        batch_thread_started = 1;
    else fprintf(stderr, "[stats] batch thread create failed\n");
#endif
}

// ---------------------- Cleanup ----------------------
void stats_cleanup(void) {
#ifdef _WIN32
    if (batch_stop_event) SetEvent(batch_stop_event);
    if (batch_thread_handle) {
        WaitForSingleObject(batch_thread_handle, 5000);
        CloseHandle(batch_thread_handle);
        batch_thread_handle = NULL;
    }
    if (batch_stop_event) { CloseHandle(batch_stop_event); batch_stop_event = NULL; }
#else
    if (batch_thread_started) {
        batch_stop = 1;
        pthread_join(batch_thread_handle, NULL);
        batch_thread_started = 0;
    }
#endif
#ifdef HAVE_LIBPQ
    if (pg_conn) { PQfinish(pg_conn); pg_conn = NULL; }
#endif
    lock_destroy();
}

// ---------------------- Increment counters ----------------------
void stats_increment(const char *proto, uint32_t pkt_len) {
    lock();

    stats.total_packets++;
    stats.total_bytes += pkt_len;

    if (strcmp(proto, "ETH") == 0)      { stats.ethernet++; stats.ethernet_bytes += pkt_len; }
    else if (strcmp(proto, "IPv4") == 0){ stats.ipv4++; stats.ipv4_bytes += pkt_len; }
    else if (strcmp(proto, "IPv6") == 0){ stats.ipv6++; stats.ipv6_bytes += pkt_len; }
    else if (strcmp(proto, "TCP") == 0) { stats.tcp++; stats.tcp_bytes += pkt_len; }
    else if (strcmp(proto, "UDP") == 0) { stats.udp++; stats.udp_bytes += pkt_len; }
    else if (strcmp(proto, "ICMP") == 0){ stats.icmp++; stats.icmp_bytes += pkt_len; }
    else if (strcmp(proto, "ARP") == 0) { stats.arp++; stats.arp_bytes += pkt_len; }
    else if (strcmp(proto, "DNS") == 0) { stats.dns++; stats.dns_bytes += pkt_len; }
    else if (strcmp(proto, "HTTP")==0)  { stats.http++; stats.http_bytes += pkt_len; }
    else if (strcmp(proto, "HTTPS")==0) { stats.https++; stats.https_bytes += pkt_len; }
    else if (strcmp(proto, "DHCP")==0)  { stats.dhcp++; stats.dhcp_bytes += pkt_len; }

    unlock();
}

// Format stats as JSON string
// pretty=1: pretty-printed with newlines; pretty=0: compact
int stats_format_json(char *out, int outlen, const ProtocolStats *snap, int pretty) {
    if (pretty) {
        return snprintf(out, (size_t)outlen,
            "{\n"
            "  \"total_packets\": %" PRIu64 ",\n"
            "  \"total_bytes\": %" PRIu64 ",\n"
            "  \"ethernet\": %" PRIu64 ", \"ethernet_bytes\": %" PRIu64 ",\n"
            "  \"ipv4\": %" PRIu64 ", \"ipv4_bytes\": %" PRIu64 ",\n"
            "  \"ipv6\": %" PRIu64 ", \"ipv6_bytes\": %" PRIu64 ",\n"
            "  \"tcp\": %" PRIu64 ", \"tcp_bytes\": %" PRIu64 ",\n"
            "  \"udp\": %" PRIu64 ", \"udp_bytes\": %" PRIu64 ",\n"
            "  \"icmp\": %" PRIu64 ", \"icmp_bytes\": %" PRIu64 ",\n"
            "  \"arp\": %" PRIu64 ", \"arp_bytes\": %" PRIu64 ",\n"
            "  \"dns\": %" PRIu64 ", \"dns_bytes\": %" PRIu64 ",\n"
            "  \"http\": %" PRIu64 ", \"http_bytes\": %" PRIu64 ",\n"
            "  \"https\": %" PRIu64 ", \"https_bytes\": %" PRIu64 ",\n"
            "  \"dhcp\": %" PRIu64 ", \"dhcp_bytes\": %" PRIu64 "\n"
            "}\n",
            snap->total_packets, snap->total_bytes,
            snap->ethernet, snap->ethernet_bytes,
            snap->ipv4, snap->ipv4_bytes,
            snap->ipv6, snap->ipv6_bytes,
            snap->tcp, snap->tcp_bytes,
            snap->udp, snap->udp_bytes,
            snap->icmp, snap->icmp_bytes,
            snap->arp, snap->arp_bytes,
            snap->dns, snap->dns_bytes,
            snap->http, snap->http_bytes,
            snap->https, snap->https_bytes,
            snap->dhcp, snap->dhcp_bytes
        );
    } else {
        return snprintf(out, (size_t)outlen,
            "{\"total_packets\":%llu,\"total_bytes\":%llu,"
            "\"ethernet\":%llu,\"ethernet_bytes\":%llu,"
            "\"ipv4\":%llu,\"ipv4_bytes\":%llu,\"ipv6\":%llu,\"ipv6_bytes\":%llu,"
            "\"tcp\":%llu,\"tcp_bytes\":%llu,\"udp\":%llu,\"udp_bytes\":%llu,"
            "\"icmp\":%llu,\"icmp_bytes\":%llu,\"arp\":%llu,\"arp_bytes\":%llu,"
            "\"dns\":%llu,\"dns_bytes\":%llu,\"http\":%llu,\"http_bytes\":%llu,"
            "\"https\":%llu,\"https_bytes\":%llu,\"dhcp\":%llu,\"dhcp_bytes\":%llu}",
            (unsigned long long)snap->total_packets, (unsigned long long)snap->total_bytes,
            (unsigned long long)snap->ethernet, (unsigned long long)snap->ethernet_bytes,
            (unsigned long long)snap->ipv4, (unsigned long long)snap->ipv4_bytes,
            (unsigned long long)snap->ipv6, (unsigned long long)snap->ipv6_bytes,
            (unsigned long long)snap->tcp, (unsigned long long)snap->tcp_bytes,
            (unsigned long long)snap->udp, (unsigned long long)snap->udp_bytes,
            (unsigned long long)snap->icmp, (unsigned long long)snap->icmp_bytes,
            (unsigned long long)snap->arp, (unsigned long long)snap->arp_bytes,
            (unsigned long long)snap->dns, (unsigned long long)snap->dns_bytes,
            (unsigned long long)snap->http, (unsigned long long)snap->http_bytes,
            (unsigned long long)snap->https, (unsigned long long)snap->https_bytes,
            (unsigned long long)snap->dhcp, (unsigned long long)snap->dhcp_bytes
        );
    }
}

// ---------------------- JSON Save/Load (atomic, lock-free I/O) ----------------------
int stats_save_json(const char *filename) {
    ProtocolStats snap;
    lock(); snap = stats; unlock();

    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.tmp", filename);
    FILE *fp = fopen(tmp, "w");
    if (!fp) return -1;

    char json[2048];
    stats_format_json(json, sizeof(json), &snap, 1);
    if (fprintf(fp, "%s", json) < 0) {
        fclose(fp);
        remove(tmp);
        return -1;
    }

    if (fclose(fp) != 0) { remove(tmp); return -1; }
    // Atomic replace (POSIX). On Windows rename() fails if dest exists, so retry after remove.
    if (rename(tmp, filename) != 0) {
        remove(filename);
        if (rename(tmp, filename) != 0) { remove(tmp); return -1; }
    }
    return 0;
}

int stats_load_json(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) return -1;

    // Parse without holding the lock (no lock-held I/O), then commit.
    ProtocolStats tmp; memset(&tmp, 0, sizeof(tmp));
    // Seed with current values so missing keys preserve counters
    lock(); tmp = stats; unlock();
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        // Skip whitespace
        while (*p && (*p == ' ' || *p == '\t')) p++;
        // Expect '"key"' at start
        if (*p != '"') continue;
        p++;
        char key[64] = {0};
        int ki = 0;
        // Read key until '"' or buffer full
        while (*p && *p != '"' && ki < 63) {
            key[ki++] = *p++;
        }
        if (*p != '"') continue; // Unterminated key
        p++; // skip closing "
        // Skip whitespace and colon
        while (*p && (*p == ' ' || *p == '\t')) p++;
        if (*p != ':') continue;
        p++;
        // Skip whitespace
        while (*p && (*p == ' ' || *p == '\t')) p++;
        // Parse unsigned long long
        char *endptr;
        unsigned long long value = strtoull(p, &endptr, 10);
        if (endptr == p) continue; // No digits parsed
        
        if (strcmp(key,"total_packets")==0) tmp.total_packets=value;
        else if (strcmp(key,"total_bytes")==0) tmp.total_bytes=value;
        else if (strcmp(key,"ethernet")==0) tmp.ethernet=value;
        else if (strcmp(key,"ethernet_bytes")==0) tmp.ethernet_bytes=value;
        else if (strcmp(key,"ipv4")==0) tmp.ipv4=value;
        else if (strcmp(key,"ipv4_bytes")==0) tmp.ipv4_bytes=value;
        else if (strcmp(key,"ipv6")==0) tmp.ipv6=value;
        else if (strcmp(key,"ipv6_bytes")==0) tmp.ipv6_bytes=value;
        else if (strcmp(key,"tcp")==0) tmp.tcp=value;
        else if (strcmp(key,"tcp_bytes")==0) tmp.tcp_bytes=value;
        else if (strcmp(key,"udp")==0) tmp.udp=value;
        else if (strcmp(key,"udp_bytes")==0) tmp.udp_bytes=value;
        else if (strcmp(key,"icmp")==0) tmp.icmp=value;
        else if (strcmp(key,"icmp_bytes")==0) tmp.icmp_bytes=value;
        else if (strcmp(key,"arp")==0) tmp.arp=value;
        else if (strcmp(key,"arp_bytes")==0) tmp.arp_bytes=value;
        else if (strcmp(key,"dns")==0) tmp.dns=value;
        else if (strcmp(key,"dns_bytes")==0) tmp.dns_bytes=value;
        else if (strcmp(key,"http")==0) tmp.http=value;
        else if (strcmp(key,"http_bytes")==0) tmp.http_bytes=value;
        else if (strcmp(key,"https")==0) tmp.https=value;
        else if (strcmp(key,"https_bytes")==0) tmp.https_bytes=value;
        else if (strcmp(key,"dhcp")==0) tmp.dhcp=value;
        else if (strcmp(key,"dhcp_bytes")==0) tmp.dhcp_bytes=value;
    }
    fclose(fp);
    lock(); stats = tmp; unlock();
    return 0;
}

// ---------------------- PostgreSQL (snapshot, reconnect) ----------------------
int stats_save_postgres(const char *conninfo) {
    (void)conninfo;
#ifndef HAVE_LIBPQ
    return -1;
#else
    if (!postgres_conninfo[0]) return -1;
    if (!pg_conn) pg_connect();
    if (!pg_conn) return -1;
    if (PQstatus(pg_conn) == CONNECTION_BAD) {
        PQreset(pg_conn);
        if (PQstatus(pg_conn) != CONNECTION_OK) return -1;
    }

    ProtocolStats snap;
    lock(); snap = stats; unlock();

    char query[2048];
    snprintf(query, sizeof(query),
        "INSERT INTO protocol_stats("
        "interval_start,total_packets,total_bytes,"
        "ethernet,ethernet_bytes,ipv4,ipv4_bytes,ipv6,ipv6_bytes,"
        "tcp,tcp_bytes,udp,udp_bytes,icmp,icmp_bytes,arp,arp_bytes,"
        "dns,dns_bytes,http,http_bytes,https,https_bytes,dhcp,dhcp_bytes"
        ") VALUES (NOW(),%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,"
        "%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu);",
        (unsigned long long)snap.total_packets, (unsigned long long)snap.total_bytes,
        (unsigned long long)snap.ethernet, (unsigned long long)snap.ethernet_bytes,
        (unsigned long long)snap.ipv4, (unsigned long long)snap.ipv4_bytes,
        (unsigned long long)snap.ipv6, (unsigned long long)snap.ipv6_bytes,
        (unsigned long long)snap.tcp, (unsigned long long)snap.tcp_bytes,
        (unsigned long long)snap.udp, (unsigned long long)snap.udp_bytes,
        (unsigned long long)snap.icmp, (unsigned long long)snap.icmp_bytes,
        (unsigned long long)snap.arp, (unsigned long long)snap.arp_bytes,
        (unsigned long long)snap.dns, (unsigned long long)snap.dns_bytes,
        (unsigned long long)snap.http, (unsigned long long)snap.http_bytes,
        (unsigned long long)snap.https, (unsigned long long)snap.https_bytes,
        (unsigned long long)snap.dhcp, (unsigned long long)snap.dhcp_bytes
    );

    PGresult *res = PQexec(pg_conn, query);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        printf("[!] Postgres insert failed: %s\n", PQerrorMessage(pg_conn));
        PQclear(res);
        return -1;
    }
    PQclear(res);

    // Reset for next interval (only after successful insert)
    lock(); memset(&stats, 0, sizeof(stats)); unlock();
    return 0;
#endif
}

// ---------------------- Batch thread ----------------------
#ifdef _WIN32
DWORD WINAPI stats_batch_thread(LPVOID lpParam) {
    (void)lpParam;
    for (;;) {
        DWORD w = WaitForSingleObject(batch_stop_event, batch_ms);
        if (w == WAIT_OBJECT_0) break;
        stats_save_postgres(postgres_conninfo);
        stats_save_json(JSON_FILE);
    }
    return 0;
}
#else
void *stats_batch_thread(void *arg) {
    (void)arg;
    while (!batch_stop) {
        for (int slept = 0; slept < batch_ms && !batch_stop; slept += 200)
            sleep_ms(200);
        if (batch_stop) break;
        stats_save_postgres(postgres_conninfo);
        stats_save_json(JSON_FILE);
    }
    return NULL;
}
#endif
