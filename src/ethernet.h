// Ethernet frame parsing
#ifndef ETHERNET_H
#define ETHERNET_H

#include <pcap.h>

void parse_ethernet(const u_char *data, int size);

#endif
