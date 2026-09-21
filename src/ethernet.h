// Ethernet frame parsing
#ifndef ETHERNET_H
#define ETHERNET_H

#ifndef _WIN32
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <sys/types.h>
#endif
#include <pcap.h>

void parse_ethernet(const u_char *data, int size);

#endif
