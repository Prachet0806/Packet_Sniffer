// Ethernet frame parsing
#include "ethernet.h"
#include "ip.h"
#include "arp.h"
#include "icmp.h"
#include "tcp.h"
#include "udp.h"

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
        printf("Ethernet: Truncated frame\n");
        return;
    }

    struct eth_header *eth = (struct eth_header *)data;

    printf("\n[Ethernet] Src MAC %02X:%02X:%02X:%02X:%02X:%02X, ",
           eth->src[0], eth->src[1], eth->src[2], eth->src[3], eth->src[4], eth->src[5]);
    printf("Dst MAC %02X:%02X:%02X:%02X:%02X:%02X, Type 0x%04X\n",
           eth->dest[0], eth->dest[1], eth->dest[2], eth->dest[3], eth->dest[4], eth->dest[5],
           ntohs(eth->type));

    int eth_type = ntohs(eth->type);
    const u_char *payload = data + sizeof(struct eth_header);
    int payload_size = size - sizeof(struct eth_header);

    switch (eth_type) {
        case 0x0800:  // IPv4
            parse_ipv4(payload, payload_size);
            break;
        case 0x86DD:  // IPv6
            parse_ipv6(payload, payload_size);
            break;
        case 0x0806:  // ARP
            parse_arp(payload, payload_size);
            break;
        default:
            printf("Ethernet: Unsupported type 0x%04X\n", eth_type);
            break;
    }
}
