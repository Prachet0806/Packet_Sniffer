// ICMP packet parsing
#include "icmp.h"
#include "stats.h"
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
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
        case 3:
            printf("ICMPv6: Time Exceeded (code=%u)\n", h.code); break;
        default:
            printf("ICMPv6: Type=%u Code=%u\n", h.type, h.code);
            break;
    }
}
