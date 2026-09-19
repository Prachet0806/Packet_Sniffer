// Ethernet frame parsing
#ifndef ETHERNET_H
#define ETHERNET_H

#ifndef _WIN32
#include <sys/types.h>
#endif
#include <pcap.h>

void parse_ethernet(const u_char *data, int size);

#endif
