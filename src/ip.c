#include "ip.h"
#include "icmp.h"
#include "tcp.h"
#include "udp.h"
#include "stats.h"

#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

static int print_ipv4_addresses(const ipv4_header_t *ip,
                                 char *src, int srcLen,
                                 char *dst, int dstLen) {
    struct in_addr s, d;
    memcpy(&s, &ip->src_addr, 4);
    memcpy(&d, &ip->dst_addr, 4);
    if (!inet_ntop(AF_INET, &s, src, (socklen_t)srcLen)) { snprintf(src, srcLen, "?"); return -1; }
    if (!inet_ntop(AF_INET, &d, dst, (socklen_t)dstLen)) { snprintf(dst, dstLen, "?"); return -1; }
    return 0;
}

static int print_ipv6_addresses(const ipv6_header_t *ip6,
                                 char *src, int srcLen,
                                 char *dst, int dstLen) {
    if (!inet_ntop(AF_INET6, &ip6->src, src, (socklen_t)srcLen)) { snprintf(src, srcLen, "?"); return -1; }
    if (!inet_ntop(AF_INET6, &ip6->dst, dst, (socklen_t)dstLen)) { snprintf(dst, dstLen, "?"); return -1; }
    return 0;
}

// IPv6 extension parsing. Returns final transport protocol or -1 on error.
// *payload_ptr/*payload_size_ptr updated to transport header on success.
static int parse_ipv6_extensions(const u_char **payload_ptr, int *payload_size_ptr,
                                u_char initial_next_header) {
    const u_char *start = *payload_ptr;
    const u_char *current = start;
    int remaining = *payload_size_ptr;
    u_char next_header = initial_next_header;

    printf("IPv6: Extension Headers: ");

    // No extension headers: fast path
    if (next_header == 6 || next_header == 17 || next_header == 58) {
        printf("-> Transport (0x%02X)\n", next_header);
        return next_header;
    }
    if (next_header == 50 || next_header == 51) {
        printf("-> %s (encrypted, no transport parse)\n",
               next_header == 50 ? "ESP" : "AH");
        return -1;
    }

    for (int hops = 0; hops < 16 && remaining > 0; hops++) {
        if (next_header == 6 || next_header == 17 || next_header == 58) {
            printf("-> Transport (0x%02X)\n", next_header);
            *payload_ptr = current;
            *payload_size_ptr = remaining;
            return next_header;
        }
        if (next_header == 50 || next_header == 51) {
            printf("-> %s, stop\n", next_header == 50 ? "ESP" : "AH");
            return -1;
        }
        if (remaining < 2) {
            printf("-> Truncated extension header\n");
            return -1;
        }
        u_char ext_next = current[0];
        u_char ext_len_field = current[1];

        const u_char *old_current = current;
        int consumed = 0;

        switch (next_header) {
            case 0:   // Hop-by-Hop
            case 60:  // Destination Options
            case 43: { // Routing
                if (remaining < 8) {
                    printf("-> Truncated ext %u\n", next_header);
                    return -1;
                }
                consumed = (ext_len_field + 1) * 8;
                if (next_header == 43 && remaining >= 4) {
                    printf("Routing (type=%u, segleft=%u, %dB) -> ",
                           current[2], current[3], consumed);
                } else if (next_header == 0) {
                    printf("Hop-by-Hop (%dB) -> ", consumed);
                } else {
                    printf("DestOpts (%dB) -> ", consumed);
                }
                if (consumed <= 0 || consumed > remaining) {
                    printf("-> Bad ext length\n");
                    return -1;
                }
                break;
            }
            case 44: { // Fragment (fixed 8 bytes, no hdr_ext_len semantics)
                if (remaining < (int)sizeof(ipv6_fragment_t)) {
                    printf("-> Truncated Fragment header\n");
                    return -1;
                }
                ipv6_fragment_t frag;
                memcpy(&frag, current, sizeof(frag));
                unsigned off_m = ntohs(frag.frag_offset_res_m);
                int frag_offset = (off_m >> 3) * 8;
                int mf = off_m & 0x0001;
                printf("Fragment (offset=%u, MF=%u, id=0x%08X) -> ",
                       frag_offset, mf, (unsigned)ntohl(frag.id));
                if (frag_offset != 0) {
                    printf("(non-first fragment, stop)\n");
                    return -1;
                }
                consumed = 8;
                break;
            }
            default: {
                // Unknown: do NOT guess length; stop to avoid misparse
                printf("-> Unknown ext 0x%02X, stop\n", next_header);
                return -1;
            }
        }

        if (consumed <= 0 || current + consumed <= old_current ||
            consumed > remaining) {
            printf("-> Loop/bad length detected\n");
            return -1;
        }
        current += consumed;
        remaining -= consumed;
        next_header = ext_next;
        (void)start;
    }

    if (next_header == 6 || next_header == 17 || next_header == 58) {
        printf("-> Transport (0x%02X)\n", next_header);
        *payload_ptr = current;
        *payload_size_ptr = remaining;
        return next_header;
    }
    printf("-> End/too many headers\n");
    return -1;
}

void parse_ipv4(const u_char *data, int size) {
    if (size < (int)sizeof(ipv4_header_t)) {
        printf("IPv4: Truncated header\n");
        return;
    }

    ipv4_header_t ip;
    memcpy(&ip, data, sizeof(ip));
    int ihl = (ip.ver_ihl & 0x0F) * 4;
    int version = (ip.ver_ihl >> 4) & 0x0F;
    if (version != 4) { printf("IPv4: Bad version %d\n", version); return; }
    int total_len = ntohs(ip.total_length);

    if (ihl < 20 || ihl > size) {
        printf("IPv4: Invalid IHL=%d\n", ihl);
        return;
    }
    if (total_len < ihl || total_len > size) {
        printf("IPv4: total_len %d inconsistent with captured %d; using captured\n",
               total_len, size);
        total_len = size;
    }

    stats_increment("IPv4", (uint32_t)size);

    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    print_ipv4_addresses(&ip, src, sizeof(src), dst, sizeof(dst));

    unsigned short ff = ntohs(ip.flags_fragment);
    int more_frags = (ff & 0x2000) != 0;
    int frag_offset = (ff & 0x1FFF) * 8;

    printf("IPv4: %s -> %s, TTL=%u, Proto=%u, Len=%d",
           src, dst, ip.ttl, ip.protocol, total_len);
    if (more_frags || frag_offset)
        printf("  [fragment %s offset=%d]", more_frags ? "MF" : "", frag_offset);
    printf("\n");

    const u_char *payload = data + ihl;
    int payload_size = total_len - ihl;
    if (payload_size < 0) payload_size = 0;

    if (frag_offset != 0) {
        printf("IPv4: non-first fragment, skipping transport parse\n");
        return;
    }

    switch (ip.protocol) {
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
            printf("IPv4: Unsupported protocol %u\n", ip.protocol);
            break;
    }
}

void parse_ipv6(const u_char *data, int size) {
    if (size < (int)sizeof(ipv6_header_t)) {
        printf("IPv6: Truncated header\n");
        return;
    }

    ipv6_header_t ip6;
    memcpy(&ip6, data, sizeof(ip6));
    char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
    print_ipv6_addresses(&ip6, src, sizeof(src), dst, sizeof(dst));

    int payload_len = ntohs(ip6.payload_len);
    if (payload_len == 0) {
        // Jumbo payload (RFC 2675) or exact fit; use captured remainder
        payload_len = size - (int)sizeof(ipv6_header_t);
        printf("IPv6: Jumbo/unspecified payload len, using captured %d\n", payload_len);
    } else if (payload_len + (int)sizeof(ipv6_header_t) > size) {
        printf("IPv6: payload_len %d exceeds captured %d; clamping\n",
               payload_len, size - (int)sizeof(ipv6_header_t));
        payload_len = size - (int)sizeof(ipv6_header_t);
    }
    if (payload_len < 0) payload_len = 0;

    stats_increment("IPv6", (uint32_t)size);

    printf("IPv6: %s -> %s, HopLimit=%u, NextHdr=%u, PayloadLen=%d\n",
           src, dst, ip6.hop_limit, ip6.next_header, payload_len);

    const u_char *payload = data + sizeof(ipv6_header_t);
    int payload_size = payload_len;

    int final_protocol = parse_ipv6_extensions(&payload, &payload_size, ip6.next_header);

    if (final_protocol == -1) {
        printf("IPv6: extension/transport not parseable (see above)\n");
        return;
    }

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
