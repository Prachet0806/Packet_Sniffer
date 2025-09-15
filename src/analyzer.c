// Packet analysis implementation
#include "analyzer.h"
#include "ethernet.h"
#include <stdio.h>

void analyze_packet(const struct pcap_pkthdr *header, const u_char *pkt_data) {
    printf("\n[+] Packet captured: length %d bytes\n", header->len);
    parse_ethernet(pkt_data, header->len);
}
