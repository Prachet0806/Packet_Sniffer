// stats.h - Header file for statistics functions
#ifndef STATS_H
#define STATS_H

#include <windows.h>
#include <stdint.h>  // For fixed-width types like uint32_t

#ifdef __cplusplus
extern "C" {
#endif

// Structure to store protocol-wise statistics
// Using 64-bit counters to prevent overflow on long-running captures
typedef struct {
    uint64_t total_packets;
    uint64_t ethernet;
    uint64_t ipv4;
    uint64_t ipv6;
    uint64_t tcp;
    uint64_t udp;
    uint64_t icmp;
    uint64_t arp;
    uint64_t dns;
    uint64_t http;
    uint64_t https;
    uint64_t dhcp;
} ProtocolStats;

// Global stats object (thread-safe via atomic operations)
extern ProtocolStats stats;

// Initialization and cleanup
void stats_init(const char *conninfo);   // <-- make sure it takes conninfo
void stats_cleanup(void);

// Increment stats (thread-safe)
void stats_increment(const char *proto);

// Save/load stats to/from JSON file (thread-safe)
int stats_save_json(const char *filename);
int stats_load_json(const char *filename);

// Save stats to PostgreSQL (thread-safe)
int stats_save_postgres(const char *conninfo);

#ifdef __cplusplus
}
#endif

#endif // STATS_H
