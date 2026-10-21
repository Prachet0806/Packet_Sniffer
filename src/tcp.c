#include "logger.h"
#include "tcp.h"
#include "http.h"
#include "https.h"
#include "dns.h"
#include "stats.h"
#include "security.h"
#include "stream.h"
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

static void print_flags(u_char f) {
    LOG_DEBUG_SIMPLE(" [");
    if (f & 0x80)
        LOG_DEBUG_SIMPLE("CWR ");
    if (f & 0x40)
        LOG_DEBUG_SIMPLE("ECE ");
    if (f & 0x20)
        LOG_DEBUG_SIMPLE("URG ");
    if (f & 0x10)
        LOG_DEBUG_SIMPLE("ACK ");
    if (f & 0x08)
        LOG_DEBUG_SIMPLE("PSH ");
    if (f & 0x04)
        LOG_DEBUG_SIMPLE("RST ");
    if (f & 0x02)
        LOG_DEBUG_SIMPLE("SYN ");
    if (f & 0x01)
        LOG_DEBUG_SIMPLE("FIN ");
    LOG_DEBUG_SIMPLE("]");
}

void parse_tcp(const u_char *data, int size, const char *src_ip, const char *dst_ip) {
    if (size < (int)sizeof(tcp_header_t)) {
        stats_note("truncated");
        LOG_DEBUG_SIMPLE("TCP: Truncated header\n");
        return;
    }

    tcp_header_t tcp;
    memcpy(&tcp, data, sizeof(tcp));
    int hdr_len = ((tcp.data_offset_reserved >> 4) & 0x0F) * 4;
    if (hdr_len < 20 || hdr_len > size) {
        stats_note("malformed");
        LOG_DEBUG_SIMPLE("TCP: Invalid header length %d\n", hdr_len);
        return;
    }

    stats_increment("TCP", (uint32_t)size);

    unsigned src_port = ntohs(tcp.src_port);
    unsigned dst_port = ntohs(tcp.dst_port);
    LOG_DEBUG_SIMPLE("TCP: %s:%u -> %s:%u, Seq=%u Ack=%u, Win=%u", src_ip, src_port, dst_ip,
                     dst_port, (unsigned)ntohl(tcp.seq_num), (unsigned)ntohl(tcp.ack_num),
                     ntohs(tcp.window));
    print_flags(tcp.flags);
    LOG_DEBUG_SIMPLE("\n");
    security_tcp_syn(src_ip, dst_ip, (uint16_t)src_port, (uint16_t)dst_port, tcp.flags);

    const u_char *payload = data + hdr_len;
    int plen = size - hdr_len;

    stream_feed(payload, plen, src_ip, dst_ip, (uint16_t)src_port, (uint16_t)dst_port,
                (uint32_t)ntohl(tcp.seq_num), tcp.flags);
}
