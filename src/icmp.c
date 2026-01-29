// ICMP packet parsing
#include "icmp.h"
#include <stdio.h>
#include <winsock2.h>

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
    if (size < (int)sizeof(icmpv4_header_t)) {
        printf("ICMPv4: Truncated\n");
        return;
    }
    const icmpv4_header_t *h = (const icmpv4_header_t *)data;
    icmpv4_print(h);
}

void parse_icmpv6(const u_char *data, int size) {
    if (size < (int)sizeof(icmpv6_header_t)) {
        printf("ICMPv6: Truncated\n");
        return;
    }
    const icmpv6_header_t *h = (const icmpv6_header_t *)data;

    switch (h->type) {
        case 128: // Echo Request
            if (size >= 8) {
                u_short id, seq;
                memcpy(&id, data + 4, sizeof(u_short));
                memcpy(&seq, data + 6, sizeof(u_short));
                printf("ICMPv6: Echo Request (id=%u, seq=%u)\n", ntohs(id), ntohs(seq));
            } else {
                printf("ICMPv6: Echo Request\n");
            }
            break;
        case 129: // Echo Reply
            if (size >= 8) {
                u_short id, seq;
                memcpy(&id, data + 4, sizeof(u_short));
                memcpy(&seq, data + 6, sizeof(u_short));
                printf("ICMPv6: Echo Reply (id=%u, seq=%u)\n", ntohs(id), ntohs(seq));
            } else {
                printf("ICMPv6: Echo Reply\n");
            }
            break;
        case 133: printf("ICMPv6: Router Solicitation\n"); break;
        case 134: printf("ICMPv6: Router Advertisement\n"); break;
        case 135: printf("ICMPv6: Neighbor Solicitation\n"); break;
        case 136: printf("ICMPv6: Neighbor Advertisement\n"); break;
        case 1:   // Destination Unreachable (v6)
            printf("ICMPv6: Destination Unreachable (code=%u)\n", h->code); break;
        case 3:   // Time Exceeded (v6)
            printf("ICMPv6: Time Exceeded (code=%u)\n", h->code); break;
        default:
            printf("ICMPv6: Type=%u Code=%u\n", h->type, h->code);
            break;
    }
}
