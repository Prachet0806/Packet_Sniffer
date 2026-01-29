// UDP packet parsing
#ifndef UDP_H
#define UDP_H

#include <pcap.h>

#pragma pack(push, 1)
typedef struct {
    u_short src_port;
    u_short dst_port;
    u_short len;
    u_short checksum;
} udp_header_t;
#pragma pack(pop)

// API
void parse_udp(const u_char *data, int size, const char *src_ip, const char *dst_ip);

#endif // UDP_H
