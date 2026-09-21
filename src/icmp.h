// ICMP packet parsing
#ifndef ICMP_H
#define ICMP_H

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

#pragma pack(push, 1)
// ICMPv4 header
typedef struct {
    u_char  type;
    u_char  code;
    u_short checksum;
    u_short id;
    u_short seq;
} icmpv4_header_t;

// ICMPv6 header
typedef struct {
    u_char  type;
    u_char  code;
    u_short checksum;
} icmpv6_header_t;
#pragma pack(pop)


// API
void parse_icmp(const u_char *data, int size);
void parse_icmpv6(const u_char *data, int size);

#endif // ICMP_H
