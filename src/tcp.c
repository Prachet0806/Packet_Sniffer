#include "tcp.h"
#include "http.h"
#include "https.h"
#include "dns.h"
#include "stats.h"
#include "security.h"
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

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

static int looks_like_http(const u_char *p, int n) {
    static const char *methods[] = {"GET ", "POST", "HEAD ", "PUT ", "DELETE ",
        "OPTIONS ", "PATCH ", "HTTP/"};
    if (n < 4) return 0;
    for (unsigned i = 0; i < sizeof(methods)/sizeof(methods[0]); i++) {
        size_t L = strlen(methods[i]);
        if (n >= (int)L && memcmp(p, methods[i], L) == 0) return 1;
    }
    return 0;
}

static int looks_like_tls(const u_char *p, int n) {
    if (n < 5) return 0;
    if (p[0] < 0x14 || p[0] > 0x17) return 0;
    unsigned ver = ((unsigned)p[1] << 8) | p[2];
    if (ver < 0x0301 || ver > 0x0304) return 0;
    return 1;
}

void parse_tcp(const u_char *data, int size, const char *src_ip, const char *dst_ip) {
    if (size < (int)sizeof(tcp_header_t)) {
        printf("TCP: Truncated header\n");
        return;
    }

    tcp_header_t tcp;
    memcpy(&tcp, data, sizeof(tcp));
    int hdr_len = ((tcp.data_offset_reserved >> 4) & 0x0F) * 4;
    if (hdr_len < 20 || hdr_len > size) {
        printf("TCP: Invalid header length %d\n", hdr_len);
        return;
    }

    stats_increment("TCP", (uint32_t)size);

    unsigned src_port = ntohs(tcp.src_port);
    unsigned dst_port = ntohs(tcp.dst_port);
    printf("TCP: %s:%u -> %s:%u, Seq=%u Ack=%u, Win=%u",
           src_ip, src_port,
           dst_ip, dst_port,
           (unsigned)ntohl(tcp.seq_num), (unsigned)ntohl(tcp.ack_num),
           ntohs(tcp.window));
    print_flags(tcp.flags);
    printf("\n");
    security_tcp_syn(src_ip, dst_ip, (uint16_t)src_port, (uint16_t)dst_port, tcp.flags);

    const u_char *payload = data + hdr_len;
    int plen = size - hdr_len;
    if (plen <= 0) return;

    // DNS over TCP (port 53): 2-byte length prefix
    if ((src_port == 53 || dst_port == 53) && plen > 2) {
        unsigned dns_len = ((unsigned)payload[0] << 8) | payload[1];
        if ((int)dns_len + 2 <= plen) {
            security_set_peer(src_ip, dst_ip);
            security_dns_query(src_ip, dst_ip, payload + 2, (int)dns_len);
            parse_dns(payload + 2, dns_len);
            return;
        }
    }

    int http_port = (src_port == 80 || dst_port == 80 || src_port == 8080 ||
                     dst_port == 8080 || src_port == 8000 || dst_port == 8000);
    int tls_port = (src_port == 443 || dst_port == 443 || src_port == 8443 || dst_port == 8443);

    if (http_port || looks_like_http(payload, plen)) {
        parse_http(payload, plen, src_ip, dst_ip,
                   (unsigned short)src_port, (unsigned short)dst_port);
    } else if (tls_port || looks_like_tls(payload, plen)) {
        parse_https(payload, plen, src_ip, dst_ip,
                    (unsigned short)src_port, (unsigned short)dst_port);
    }
}
