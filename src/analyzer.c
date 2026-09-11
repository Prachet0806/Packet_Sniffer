// Packet analysis implementation (DLT-aware)
#include "analyzer.h"
#include "ethernet.h"
#include "ip.h"
#include "sniffer.h"
#include <stdio.h>
#include <string.h>

void analyze_packet(const struct pcap_pkthdr *header, const u_char *pkt_data) {
    int caplen = (int)header->caplen;
    printf("\n[+] Packet captured: caplen %d bytes (wire %d bytes, DLT=%d)\n",
           caplen, header->len, sniffer_datalink());
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
