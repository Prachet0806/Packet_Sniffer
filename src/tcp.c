#include "tcp.h"
#include <stdio.h>
#include <winsock2.h>

static void print_flags(u_char f) {
    printf(" [");
    if (f & 0x80) printf("CWR ");
    if (f & 0x40) printf("ECE ");
    if (f & 0x20) printf("URG ");
    if (f & 0x10) printf("ACK ");
    if (f & 0x08) printf("PSH ");
    if (f & 0x04) printf("RST ");
    if (f & 0x02) printf("SYN ");
    if (f & 0x01) printf("FIN ");
    printf("]");
}

void parse_tcp(const u_char *data, int size, const char *src_ip, const char *dst_ip) {
    if (size < (int)sizeof(tcp_header_t)) {
        printf("TCP: Truncated header\n");
        return;
    }

    const tcp_header_t *tcp = (const tcp_header_t *)data;
    int hdr_len = ((tcp->data_offset_reserved >> 4) & 0x0F) * 4;
    if (hdr_len < 20 || hdr_len > size) {
        printf("TCP: Invalid header length %d\n", hdr_len);
        return;
    }

    printf("TCP: %s:%u -> %s:%u, Seq=%u Ack=%u, Win=%u",
           src_ip, ntohs(tcp->src_port),
           dst_ip, ntohs(tcp->dst_port),
           ntohl(tcp->seq_num), ntohl(tcp->ack_num),
           ntohs(tcp->window));
    print_flags(tcp->flags);
    printf("\n");

}
