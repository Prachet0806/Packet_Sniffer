#include "udp.h"
#include "dns.h"
#include "dhcp.h"
#include "stats.h"
#include "security.h"
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

void parse_udp(const u_char *data, int size, const char *src_ip, const char *dst_ip) {
    if (size < (int)sizeof(udp_header_t)) {
        printf("UDP: Truncated header\n");
        return;
    }

    udp_header_t udp;
    memcpy(&udp, data, sizeof(udp));
    int ulen = ntohs(udp.len); // header + payload
    if (ulen < (int)sizeof(udp_header_t) || ulen > size) {
        printf("UDP: Invalid length field (%d), available=%d; using available\n", ulen, size);
        ulen = size;
    }

    stats_increment("UDP", (uint32_t)size);

    u_short src_port = ntohs(udp.src_port);
    u_short dst_port = ntohs(udp.dst_port);

    printf("UDP: %s:%u -> %s:%u, Len=%d\n",
           src_ip, src_port, dst_ip, dst_port, ulen);

    // DNS on port 53 (also mDNS 5353 carries DNS-like payloads)
    if (src_port == 53 || dst_port == 53 || src_port == 5353 || dst_port == 5353) {
        const u_char *payload = data + sizeof(udp_header_t);
        int payload_size = ulen - (int)sizeof(udp_header_t);
        if (payload_size > 0) {
            security_set_peer(src_ip, dst_ip);
            security_dns_query(src_ip, dst_ip, payload, payload_size);
            parse_dns(payload, payload_size);
        }
    }
    // DHCP on ports 67/68
    else if (src_port == DHCP_SERVER_PORT || dst_port == DHCP_SERVER_PORT ||
             src_port == DHCP_CLIENT_PORT || dst_port == DHCP_CLIENT_PORT) {
        const u_char *payload = data + sizeof(udp_header_t);
        int payload_size = ulen - (int)sizeof(udp_header_t);
        if (payload_size > 0) {
            parse_dhcp(payload, payload_size, src_ip, dst_ip, src_port, dst_port);
        }
    }
    // DHCPv6 on ports 546/547
    else if (src_port == DHCPV6_SERVER_PORT || dst_port == DHCPV6_SERVER_PORT ||
             src_port == DHCPV6_CLIENT_PORT || dst_port == DHCPV6_CLIENT_PORT) {
        const u_char *payload = data + sizeof(udp_header_t);
        int payload_size = ulen - (int)sizeof(udp_header_t);
        if (payload_size > 0) {
            parse_dhcpv6(payload, payload_size, src_ip, dst_ip, src_port, dst_port);
        }
    }
}
