// Ethernet frame parsing
#include "ethernet.h"
#include "ip.h"
#include "arp.h"
#include "icmp.h"
#include "tcp.h"
#include "udp.h"
#include "stats.h"
#include "logger.h"
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>

struct eth_header {
    unsigned char dest[6];
    unsigned char src[6];
    unsigned short type;
};

void parse_ethernet(const u_char *data, int size) {
    if (size < (int)sizeof(struct eth_header)) {
        LOG_WARN_SIMPLE("Ethernet: Truncated frame\n");
        return;
    }

    struct eth_header *eth = (struct eth_header *)data;
    
    stats_increment("ETH");

    LOG_DEBUG_SIMPLE("\n[Ethernet] Src MAC %02X:%02X:%02X:%02X:%02X:%02X, ",
           eth->src[0], eth->src[1], eth->src[2], eth->src[3], eth->src[4], eth->src[5]);
    LOG_DEBUG_SIMPLE("Dst MAC %02X:%02X:%02X:%02X:%02X:%02X, Type 0x%04X\n",
           eth->dest[0], eth->dest[1], eth->dest[2], eth->dest[3], eth->dest[4], eth->dest[5],
           ntohs(eth->type));

    int eth_type = ntohs(eth->type);
    const u_char *payload = data + sizeof(struct eth_header);
    int payload_size = size - sizeof(struct eth_header);
    
    // Validate payload size is non-negative
    if (payload_size < 0) {
        LOG_WARN_SIMPLE("Ethernet: Invalid payload size\n");
        return;
    }

    switch (eth_type) {
        case 0x0800:  // IPv4
            stats_increment("IPv4");
            parse_ipv4(payload, payload_size);
            break;
        case 0x86DD:  // IPv6
            stats_increment("IPv6");
            parse_ipv6(payload, payload_size);
            break;
        case 0x0806:  // ARP
            stats_increment("ARP");
            parse_arp(payload, payload_size);
            break;
        default:
            LOG_DEBUG_SIMPLE("Ethernet: Unsupported type 0x%04X\n", eth_type);
            break;
    }
}
