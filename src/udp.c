#include "udp.h"
#include "dns.h"
#include "dhcp.h"
#include "logger.h"
#include <stdio.h>
#include <winsock2.h>
#include "stats.h"
void parse_udp(const u_char *data, int size, const char *src_ip, const char *dst_ip) {
    if (size < (int)sizeof(udp_header_t)) {
        LOG_WARN_SIMPLE("UDP: Truncated header\n");
        return;
    }

    const udp_header_t *udp = (const udp_header_t *)data;
    int ulen = ntohs(udp->len); // header + payload
    if (ulen < (int)sizeof(udp_header_t) || ulen > size) {
        // Clamp or just warn; some drivers may not deliver full payload
        LOG_WARN_SIMPLE("UDP: Invalid length field (%d), available=%d\n", ulen, size);
        ulen = size;
    }

    u_short src_port = ntohs(udp->src_port);
    u_short dst_port = ntohs(udp->dst_port);

    LOG_DEBUG_SIMPLE("UDP: %s:%u -> %s:%u, Len=%d\n",
           src_ip, src_port, dst_ip, dst_port, ulen);

    const u_char *payload = data + sizeof(udp_header_t);
    int payload_size = ulen - sizeof(udp_header_t);
    
    // Validate payload size is positive and within bounds
    if (payload_size <= 0 || payload_size > (size - (int)sizeof(udp_header_t))) {
        return;
    }

    // Check for DNS traffic (port 53)
    if (src_port == 53 || dst_port == 53) {
        stats_increment("DNS");
        parse_dns(payload, payload_size);
    }
    // Check for DHCP traffic (ports 67 and 68)
    else if (src_port == DHCP_SERVER_PORT || dst_port == DHCP_SERVER_PORT ||
             src_port == DHCP_CLIENT_PORT || dst_port == DHCP_CLIENT_PORT) {
        parse_dhcp(payload, payload_size, src_ip, dst_ip, src_port, dst_port);
    }
}
