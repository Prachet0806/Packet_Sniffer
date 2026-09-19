// Packet analysis implementation (DLT-aware, log-level gated)
#include "analyzer.h"
#include "ethernet.h"
#include "ip.h"
#include "sniffer.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

static unsigned long long packet_count = 0;
static int quiet_checked = 0;
static int quiet = 0;

void analyze_packet(const struct pcap_pkthdr *header, const u_char *pkt_data) {
    packet_count++;
    if (!quiet_checked) {
        quiet_checked = 1;
        const char *q = getenv("SNIFFER_QUIET");
        if (q && (q[0] == '1' || q[0] == 'y' || q[0] == 'Y')) quiet = 1;
    }
    int caplen = (int)header->caplen;
    if (!quiet && current_log_level >= LOG_DEBUG) {
        printf("\n[+] Packet #%llu: caplen %d bytes (wire %d bytes, DLT=%d)\n",
               packet_count, caplen, header->len, sniffer_datalink());
    } else if (!quiet && packet_count % 1000 == 0) {
        printf("[*] Processed %llu packets...\n", packet_count);
    }
    if (caplen <= 0) return;

    int dlt = sniffer_datalink();
    switch (dlt) {
        case DLT_EN10MB:
            parse_ethernet(pkt_data, caplen);
            break;
        case DLT_NULL:
        case DLT_LOOP: {
            // BSD loopback: 4-byte AF family prefix
            if (caplen < 4) { printf("Loopback: truncated\n"); break; }
            unsigned fam;
            memcpy(&fam, pkt_data, 4);
            const u_char *pl = pkt_data + 4;
            int pln = caplen - 4;
            // AF_INET=2, AF_INET6=24/28/10 depending on platform
            if (fam == 2) parse_ipv4(pl, pln);
            else parse_ipv6(pl, pln);
            break;
        }
        case DLT_LINUX_SLL:
        case 114: // DLT_LINUX_SLL2
            // SLL: 16-byte header (Linux cooked capture)
            if (caplen < 16) { printf("SLL: truncated\n"); break; }
            {
                unsigned proto = ((unsigned)pkt_data[14] << 8) | pkt_data[15];
                const u_char *pl = pkt_data + 16;
                int pln = caplen - 16;
                if (proto == 0x0800) parse_ipv4(pl, pln);
                else if (proto == 0x86DD) parse_ipv6(pl, pln);
                else printf("SLL: unsupported proto 0x%04X\n", proto);
            }
            break;
        case DLT_RAW:
            // Raw IP: version nibble decides
            if (caplen < 1) break;
            if (((pkt_data[0] >> 4) & 0xF) == 6) parse_ipv6(pkt_data, caplen);
            else parse_ipv4(pkt_data, caplen);
            break;
        default:
            // Fallback: try Ethernet; many Npcap loopback captures use it
            parse_ethernet(pkt_data, caplen);
            break;
    }
}
