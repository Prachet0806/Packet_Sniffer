#include "logger.h"
// Ethernet frame parsing
#include "ethernet.h"
#include "ip.h"
#include "arp.h"
#include "icmp.h"
#include "tcp.h"
#include "udp.h"
#include "stats.h"
#include "security.h"

#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#pragma pack(push, 1)
struct eth_header {
    unsigned char dest[6];
    unsigned char src[6];
    unsigned short type;
};
struct vlan_tag {
    unsigned short tci;
    unsigned short type;
};
#pragma pack(pop)

void parse_ethernet(const u_char *data, int size) {
    if (size < (int)sizeof(struct eth_header)) {
        stats_note("truncated");
        LOG_DEBUG_SIMPLE("Ethernet: Truncated frame\n");
        return;
    }
    stats_increment("ETH", (uint32_t)size);

    struct eth_header eth;
    memcpy(&eth, data, sizeof(eth));

    LOG_DEBUG_SIMPLE("\n[Ethernet] Src MAC %02X:%02X:%02X:%02X:%02X:%02X, ", eth.src[0], eth.src[1],
                     eth.src[2], eth.src[3], eth.src[4], eth.src[5]);
    LOG_DEBUG_SIMPLE("Dst MAC %02X:%02X:%02X:%02X:%02X:%02X, Type 0x%04X\n", eth.dest[0],
                     eth.dest[1], eth.dest[2], eth.dest[3], eth.dest[4], eth.dest[5],
                     ntohs(eth.type));

    int eth_type = ntohs(eth.type);
    const u_char *payload = data + sizeof(struct eth_header);
    int payload_size = size - (int)sizeof(struct eth_header);

    // Strip stacked VLAN tags (802.1Q / 802.1ad)
    int vlan_depth = 0;
    uint32_t context = security_context_id();
    while ((eth_type == 0x8100 || eth_type == 0x88A8 || eth_type == 0x9100) && vlan_depth < 8) {
        if (payload_size < (int)sizeof(struct vlan_tag)) {
            stats_note("truncated");
            LOG_DEBUG_SIMPLE("Ethernet: Truncated VLAN tag\n");
            return;
        }
        struct vlan_tag tag;
        memcpy(&tag, payload, sizeof(tag));
        unsigned vlan_id = ntohs(tag.tci) & 0x0FFF;
        eth_type = ntohs(tag.type);
        LOG_DEBUG_SIMPLE("[VLAN] ID=%u, inner=0x%04X\n", vlan_id, eth_type);
        payload += sizeof(struct vlan_tag);
        payload_size -= (int)sizeof(struct vlan_tag);
        vlan_depth++;
        context = context * 4099 + vlan_id + 1;
        security_set_network(context);
    }

    switch (eth_type) {
    case 0x0800: // IPv4
        parse_ipv4(payload, payload_size);
        break;
    case 0x86DD: // IPv6
        parse_ipv6(payload, payload_size);
        break;
    case 0x0806: // ARP
        parse_arp(payload, payload_size);
        break;
    case 0x8035: // RARP (uses same ARP format)
        parse_arp(payload, payload_size);
        break;
    default:
        LOG_DEBUG_SIMPLE("Ethernet: Unsupported type 0x%04X\n", eth_type);
        break;
    }
}
