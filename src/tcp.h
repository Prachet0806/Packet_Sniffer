// TCP packet parsing
#ifndef TCP_H
#define TCP_H

#include <pcap.h>

#pragma pack(push, 1)
typedef struct {
    u_short src_port;
    u_short dst_port;
    u_int   seq_num;
    u_int   ack_num;
    u_char  data_offset_reserved;
    u_char  flags;
    u_short window;
    u_short checksum;
    u_short urgent_ptr;
} tcp_header_t;
#pragma pack(pop)

// API
void parse_tcp(const u_char *data, int size, const char *src_ip, const char *dst_ip);

#endif // TCP_H
