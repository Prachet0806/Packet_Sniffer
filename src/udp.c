#include "udp.h"
#include "dns.h"
#include <stdio.h>
#include <winsock2.h>

void parse_udp(const u_char *data, int size, const char *src_ip, const char *dst_ip) {
    if (size < (int)sizeof(udp_header_t)) {
        printf("UDP: Truncated header\n");
        return;
    }

    const udp_header_t *udp = (const udp_header_t *)data;
    int ulen = ntohs(udp->len); // header + payload
    if (ulen < (int)sizeof(udp_header_t) || ulen > size) {
        // Clamp or just warn; some drivers may not deliver full payload
        printf("UDP: Invalid length field (%d), available=%d\n", ulen, size);
        ulen = size;
    }

    u_short src_port = ntohs(udp->src_port);
    u_short dst_port = ntohs(udp->dst_port);

    printf("UDP: %s:%u -> %s:%u, Len=%d\n",
           src_ip, src_port, dst_ip, dst_port, ulen);

    // Check for DNS traffic (port 53)
    if (src_port == 53 || dst_port == 53) {
        const u_char *payload = data + sizeof(udp_header_t);
        int payload_size = ulen - sizeof(udp_header_t);
        if (payload_size > 0) {
            parse_dns(payload, payload_size);
        }
    }
}
