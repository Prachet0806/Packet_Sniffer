// ARP packet parsing
#ifndef ARP_H
#define ARP_H

#include <pcap.h>

#pragma pack(push, 1)
// ARP header
typedef struct {
    u_short hardware_type;
    u_short protocol_type;
    u_char  hardware_size;
    u_char  protocol_size;
    u_short operation;
    u_char  sender_mac[6];
    u_int   sender_ip;
    u_char  target_mac[6];
    u_int   target_ip;
} arp_header_t;
#pragma pack(pop)

// API
void parse_arp(const u_char *data, int size);

#endif // ARP_H
