// ICMP packet parsing
#include "icmp.h"
#include "stats.h"
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

static void icmpv4_print(const icmpv4_header_t *h) {
    switch (h->type) {
        case 0:  printf("ICMPv4: Echo Reply (id=%u, seq=%u)\n", ntohs(h->id), ntohs(h->seq)); break;
        case 3:  printf("ICMPv4: Destination Unreachable (code=%u)\n", h->code); break;
        case 4:  printf("ICMPv4: Source Quench (deprecated)\n"); break;
        case 5:  printf("ICMPv4: Redirect (code=%u)\n", h->code); break;
        case 8:  printf("ICMPv4: Echo Request (id=%u, seq=%u)\n", ntohs(h->id), ntohs(h->seq)); break;
        case 9:  printf("ICMPv4: Router Advertisement\n"); break;
        case 10: printf("ICMPv4: Router Solicitation\n"); break;
        case 11: printf("ICMPv4: Time Exceeded (code=%u)\n", h->code); break;
        case 12: printf("ICMPv4: Parameter Problem\n"); break;
        default: printf("ICMPv4: Type=%u Code=%u\n", h->type, h->code); break;
    }
}

void parse_icmp(const u_char *data, int size) {
    if (size < 4) {
        printf("ICMPv4: Truncated\n");
        return;
    }
    stats_increment("ICMP", (uint32_t)size);
    if (size < (int)sizeof(icmpv4_header_t)) {
        // Types without id/seq (e.g. dest-unreach) are only 4+ bytes
        printf("ICMPv4: Type=%u Code=%u (short)\n", data[0], data[1]);
        return;
    }
    icmpv4_header_t h;
    memcpy(&h, data, sizeof(h));
    icmpv4_print(&h);

    // Error messages (3, 5, 11, 12) embed the offending IP header + 8 bytes
    if ((h.type == 3 || h.type == 5 || h.type == 11 || h.type == 12) &&
        size >= 8 + 20) {
        const u_char *emb = data + 8;
        int embsize = size - 8;
        unsigned ver = (emb[0] >> 4) & 0xF;
        if (ver == 4 && embsize >= 20) {
            unsigned eproto = emb[9];
            char esrc[16] = "?", edst[16] = "?";
            struct in_addr a, b;
            memcpy(&a.s_addr, emb + 12, 4);
            memcpy(&b.s_addr, emb + 16, 4);
            inet_ntop(AF_INET, &a, esrc, sizeof(esrc));
            inet_ntop(AF_INET, &b, edst, sizeof(edst));
            int ihl = (emb[0] & 0x0F) * 4;
            printf("ICMPv4:   embedded %s -> %s proto=%u", esrc, edst, eproto);
            if (eproto == 6 && embsize >= ihl + 4) {
                unsigned sp = ((unsigned)emb[ihl] << 8) | emb[ihl+1];
                unsigned dp = ((unsigned)emb[ihl+2] << 8) | emb[ihl+3];
                printf(" ports %u->%u", sp, dp);
            } else if (eproto == 17 && embsize >= ihl + 4) {
                unsigned sp = ((unsigned)emb[ihl] << 8) | emb[ihl+1];
                unsigned dp = ((unsigned)emb[ihl+2] << 8) | emb[ihl+3];
                printf(" ports %u->%u", sp, dp);
            }
            printf("\n");
        }
    }
}

void parse_icmpv6(const u_char *data, int size) {
    if (size < (int)sizeof(icmpv6_header_t)) {
        printf("ICMPv6: Truncated\n");
        return;
    }
    stats_increment("ICMP", (uint32_t)size);
    icmpv6_header_t h;
    memcpy(&h, data, sizeof(h));

    switch (h.type) {
        case 128: // Echo Request
        case 129: { // Echo Reply
            const char *label = (h.type == 128) ? "Echo Request" : "Echo Reply";
            if (size >= 8) {
                u_short id_raw, seq_raw;
                memcpy(&id_raw, data + 4, 2);
                memcpy(&seq_raw, data + 6, 2);
                printf("ICMPv6: %s (id=%u, seq=%u)\n", label, ntohs(id_raw), ntohs(seq_raw));
            } else {
                printf("ICMPv6: %s\n", label);
            }
            break;
        }
        case 133: printf("ICMPv6: Router Solicitation\n"); break;
        case 134: printf("ICMPv6: Router Advertisement\n"); break;
        case 135: printf("ICMPv6: Neighbor Solicitation\n"); break;
        case 136: printf("ICMPv6: Neighbor Advertisement\n"); break;
        case 1:
            printf("ICMPv6: Destination Unreachable (code=%u)\n", h.code); break;
        case 2:
            printf("ICMPv6: Packet Too Big (code=%u)\n", h.code); break;
        case 3:
            printf("ICMPv6: Time Exceeded (code=%u)\n", h.code); break;
        case 4:
            printf("ICMPv6: Parameter Problem (code=%u)\n", h.code); break;
        default:
            printf("ICMPv6: Type=%u Code=%u\n", h.type, h.code);
            break;
    }

    // ICMPv6 errors (1-4) embed the offending packet; show its endpoints
    if ((h.type >= 1 && h.type <= 4) && size >= 8 + 40) {
        const u_char *emb = data + 8;
        char esrc[64] = "?", edst[64] = "?";
        struct in6_addr a6, b6;
        memcpy(&a6, emb + 8, 16);
        memcpy(&b6, emb + 24, 16);
        inet_ntop(AF_INET6, &a6, esrc, sizeof(esrc));
        inet_ntop(AF_INET6, &b6, edst, sizeof(edst));
        printf("ICMPv6:   embedded %s -> %s next=%u\n", esrc, edst, emb[6]);
    }
}
