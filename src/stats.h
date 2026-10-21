// stats.h - Header file for statistics functions
#ifndef STATS_H
#define STATS_H

#include <stdint.h> // For fixed-width types like uint32_t
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <pthread.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Structure to store protocol-wise statistics with byte counters
typedef struct {
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t wire_bytes, analyzed, queue_drops, allocation_drops, recording_errors;
    uint64_t malformed, truncated, unsupported, incomplete, alert_drops, state_evictions;

    uint64_t ethernet;
    uint64_t ethernet_bytes;

    uint64_t ipv4;
    uint64_t ipv4_bytes;

    uint64_t ipv6;
    uint64_t ipv6_bytes;

    uint64_t tcp;
    uint64_t tcp_bytes;

    uint64_t udp;
    uint64_t udp_bytes;

    uint64_t icmp;
    uint64_t icmp_bytes;

    uint64_t arp;
    uint64_t arp_bytes;

    uint64_t dns;
    uint64_t dns_bytes;

    uint64_t http;
    uint64_t http_bytes;

    uint64_t https;
    uint64_t https_bytes;

    uint64_t dhcp;
    uint64_t dhcp_bytes;
} ProtocolStats;

// Global stats object and lock for thread safety
extern ProtocolStats stats;
#ifdef _WIN32
extern CRITICAL_SECTION stats_cs;
DWORD WINAPI stats_batch_thread(LPVOID lpParam);
#else
extern pthread_mutex_t stats_cs;
void *stats_batch_thread(void *arg);
#endif

// Initialization and cleanup
int stats_init(const char *conninfo);
int stats_cleanup(void);

void stats_capture(uint32_t captured, uint32_t wire);
void stats_capture_at(uint32_t captured, uint32_t wire, int64_t time_us);
int stats_health_json(char *out, int size);
void stats_note(const char *kind);
void stats_snapshot(ProtocolStats *out);
int stats_db_healthy(void);
void stats_queue_alert(const char *time, const char *type, const char *src, const char *dst,
                       const char *detail);
// Increment stats (thread-safe)
void stats_increment(const char *proto, uint32_t pkt_len);

// Save/load stats to/from JSON file (thread-safe)
// NOTE: JSON is a cumulative snapshot (counters keep running).
int stats_save_json(const char *filename);
int stats_load_json(const char *filename);

// Format stats as JSON string (compact or pretty)
// Returns number of bytes written (excluding null terminator)
int stats_format_json(char *out, int outlen, const ProtocolStats *snap, int pretty);

// Save stats to PostgreSQL (thread-safe)
// NOTE: interval semantics — counters reset after a successful insert,
// unlike the cumulative JSON snapshot.
int stats_save_postgres(const char *conninfo);

#ifdef __cplusplus
}
#endif

#endif // STATS_H
