// analyzer.h - Header file for packet analysis functions
#ifndef ANALYZER_H
#define ANALYZER_H

#ifndef _WIN32
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <sys/types.h>
#include <time.h>
#endif
#include <pcap.h>

void analyze_packet(const struct pcap_pkthdr *header, const u_char *pkt_data);

#endif // ANALYZER_H
