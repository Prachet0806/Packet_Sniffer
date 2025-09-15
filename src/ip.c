#include "ip.h"
#include "icmp.h"
#include "tcp.h"
#include "udp.h"

#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>

static void print_ipv4_addresses(const ipv4_header_t *ip,
                                 char *src, int srcLen,
                                 char *dst, int dstLen) {
    inet_ntop(AF_INET, &ip->src_addr, src, srcLen);
    inet_ntop(AF_INET, &ip->dst_addr, dst, dstLen);
}

static void print_ipv6_addresses(const ipv6_header_t *ip6,
                                 char *src, int srcLen,
                                 char *dst, int dstLen) {
    inet_ntop(AF_INET6, &ip6->src, src, srcLen);
    inet_ntop(AF_INET6, &ip6->dst, dst, dstLen);
}

// IPv6 extension parsing
static int parse_ipv6_extensions(const u_char **payload_ptr, int *payload_size_ptr,
                                u_char initial_next_header) {
    const u_char *current = *payload_ptr;
    int remaining = *payload_size_ptr;
    u_char next_header = initial_next_header;

    printf("IPv6: Extension Headers: ");

    while (remaining > 0) {
        // Check for transport protocol
        switch (next_header) {
            case 6:   // TCP
            case 17:  // UDP
            case 58:  // ICMPv6
                printf("-> Transport (0x%02X)\n", next_header);
                *payload_ptr = current;
                *payload_size_ptr = remaining;
                return next_header;
        }

        if (remaining < (int)sizeof(ipv6_ext_header_t)) {
            printf("-> Truncated extension header\n");
            return -1;
        }

        const ipv6_ext_header_t *ext_hdr = (const ipv6_ext_header_t *)current;

        switch (next_header) {
            case 0: {
                if (remaining < 8) {
                    printf("-> Truncated Hop-by-Hop header\n");
                    return -1;
                }
                int hdr_len = (ext_hdr->hdr_ext_len + 1) * 8;
                printf("Hop-by-Hop (%d bytes) -> ", hdr_len);
                current += hdr_len;
                remaining -= hdr_len;
                break;
            }
            case 43: {
                if (remaining < 8) {
                    printf("-> Truncated Routing header\n");
                    return -1;
                }
                const ipv6_routing_t *routing = (const ipv6_routing_t *)current;
                int hdr_len = (ext_hdr->hdr_ext_len + 1) * 8;
                printf("Routing (type=%u, segments=%u, %d bytes) -> ",
                       routing->routing_type, routing->segments_left, hdr_len);
                current += hdr_len;
                remaining -= hdr_len;
                break;
            }
            case 44: {
                if (remaining < (int)sizeof(ipv6_fragment_t)) {
                    printf("-> Truncated Fragment header\n");
                    return -1;
                }
                const ipv6_fragment_t *frag = (const ipv6_fragment_t *)current;
                int frag_offset = (ntohs(frag->frag_offset_res_m) >> 3) * 8;
                int more_fragments = ntohs(frag->frag_offset_res_m) & 0x0001;
                printf("Fragment (offset=%u, MF=%u, id=0x%08X) -> ",
                       frag_offset, more_fragments, ntohl(frag->id));
                current += sizeof(ipv6_fragment_t);
                remaining -= sizeof(ipv6_fragment_t);
                break;
            }
            case 60: {
                if (remaining < 8) {
                    printf("-> Truncated Destination Options header\n");
                    return -1;
                }
                int hdr_len = (ext_hdr->hdr_ext_len + 1) * 8;
                printf("Dest Options (%d bytes) -> ", hdr_len);
                current += hdr_len;
                remaining -= hdr_len;
                break;
            }
            default: {
                printf("-> Unknown extension header (0x%02X)\n", next_header);
                if (remaining < 8) {
                    return -1;
                }
                int hdr_len = (ext_hdr->hdr_ext_len + 1) * 8;
                current += hdr_len;
                remaining -= hdr_len;
                break;
            }
        }

        next_header = ext_hdr->next_header;

        // Prevent loops
        if (current == *payload_ptr) {
            printf("-> Loop detected in extension headers\n");
            return -1;
        }
        *payload_ptr = current;
    }

    printf("-> End of headers\n");
    return next_header;
}

void parse_ipv4(const u_char *data, int size) {
    if (size < (int)sizeof(ipv4_header_t)) {
        printf("IPv4: Truncated header\n");
        return;
    }

    const ipv4_header_t *ip = (const ipv4_header_t *)data;
    int ihl = (ip->ver_ihl & 0x0F) * 4;
    int total_len = ntohs(ip->total_length);

    if (ihl < 20 || ihl > size) {
        printf("IPv4: Invalid IHL=%d\n", ihl);
        return;
    }
    if (total_len < ihl || total_len > size) {
        // Clamp to available bytes; some NDIS paths may not deliver full frame
        total_len = size;
    }

    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    print_ipv4_addresses(ip, src, sizeof(src), dst, sizeof(dst));

    unsigned short ff = ntohs(ip->flags_fragment);
    int more_frags = (ff & 0x2000) != 0;
    int frag_offset = (ff & 0x1FFF) * 8;

    printf("IPv4: %s -> %s, TTL=%u, Proto=%u, Len=%d",
           src, dst, ip->ttl, ip->protocol, total_len);
    if (more_frags || frag_offset)
        printf("  [fragment %s offset=%d]", more_frags ? "MF" : "", frag_offset);
    printf("\n");

    const u_char *payload = data + ihl;
    int payload_size = total_len - ihl;
    if (payload_size < 0) payload_size = 0;

    switch (ip->protocol) {
        case 1:
            parse_icmp(payload, payload_size);
            break;
        case 6:
            parse_tcp(payload, payload_size, src, dst);
            break;
        case 17:
            parse_udp(payload, payload_size, src, dst);
            break;
        default:
            printf("IPv4: Unsupported protocol %u\n", ip->protocol);
            break;
    }
}

void parse_ipv6(const u_char *data, int size) {
    if (size < (int)sizeof(ipv6_header_t)) {
        printf("IPv6: Truncated header\n");
        return;
    }

    const ipv6_header_t *ip6 = (const ipv6_header_t *)data;
    char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
    print_ipv6_addresses(ip6, src, sizeof(src), dst, sizeof(dst));

    int payload_len = ntohs(ip6->payload_len);
    if (payload_len + (int)sizeof(ipv6_header_t) > size) {
        payload_len = size - (int)sizeof(ipv6_header_t); // clamp
    }

    printf("IPv6: %s -> %s, HopLimit=%u, NextHdr=%u, PayloadLen=%d\n",
           src, dst, ip6->hop_limit, ip6->next_header, payload_len);

    const u_char *payload = data + sizeof(ipv6_header_t);
    int payload_size = payload_len;

    // Parse extension headers
    int final_protocol = parse_ipv6_extensions(&payload, &payload_size, ip6->next_header);

    if (final_protocol == -1) {
        printf("IPv6: Error parsing extension headers\n");
        return;
    }

    // Route to transport parser
    switch (final_protocol) {
        case 58:
            parse_icmpv6(payload, payload_size);
            break;
        case 6:
            parse_tcp(payload, payload_size, src, dst);
            break;
        case 17:
            parse_udp(payload, payload_size, src, dst);
            break;
        default:
            printf("IPv6: Unsupported transport protocol %u\n", final_protocol);
            break;
    }
}
