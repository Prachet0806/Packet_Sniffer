#include "tcp.h"
#include "http.h"
#include "https.h"
#include "stats.h"
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
    // Validate header length: minimum 20 bytes, maximum 60 bytes (15 * 4), and must not exceed packet size
    if (hdr_len < 20 || hdr_len > 60 || hdr_len > size) {
        printf("TCP: Invalid header length %d (size=%d)\n", hdr_len, size);
        return;
    }

    u_short src_port = ntohs(tcp->src_port);
    u_short dst_port = ntohs(tcp->dst_port);

    printf("TCP: %s:%u -> %s:%u, Seq=%u Ack=%u, Win=%u",
           src_ip, src_port,
           dst_ip, dst_port,
           ntohl(tcp->seq_num), ntohl(tcp->ack_num),
           ntohs(tcp->window));
    print_flags(tcp->flags);
    printf("\n");

    // Extract payload
    const u_char *payload = data + hdr_len;
    int payload_size = size - hdr_len;
    if (payload_size <= 0) return;

    // Application layer checks
    // Note: HTTP/HTTPS stats are incremented inside their respective parse functions
    // to avoid double counting
    if (src_port == 80 || dst_port == 80) {
        parse_http(payload, payload_size, src_ip, dst_ip, src_port, dst_port);
    }
    else if (src_port == 443 || dst_port == 443) {
        parse_https(payload, payload_size, src_ip, dst_ip, src_port, dst_port);
    }
    // Later you can add SMTP, IMAP, POP3, etc.
}