// analyzer.h - Header file for packet analysis functions
#ifndef ANALYZER_H
#define ANALYZER_H

#ifndef _WIN32
#include <sys/types.h>
#endif
#include <pcap.h>

void analyze_packet(const struct pcap_pkthdr *header, const u_char *pkt_data);

#endif // ANALYZER_H
