// IP packet parsing
#ifndef IP_H
#define IP_H

#include <pcap.h>

// IPv4 header
#pragma pack(push, 1)
typedef struct {
    u_char  ver_ihl;
    u_char  tos;
    u_short total_length;
    u_short identification;
    u_short flags_fragment;
    u_char  ttl;
    u_char  protocol;
    u_short checksum;
    u_int   src_addr;
    u_int   dst_addr;
} ipv4_header_t;

// IPv6 header
typedef struct {
    u_int   ver_tc_fl;
    u_short payload_len;
    u_char  next_header;
    u_char  hop_limit;
    struct  in6_addr src;
    struct  in6_addr dst;
} ipv6_header_t;

// IPv6 extension headers
typedef struct {
    u_char  next_header;
    u_char  hdr_ext_len;
} ipv6_ext_header_t;

// Hop-by-Hop Options
typedef struct {
    u_char  next_header;
    u_char  hdr_ext_len;
    u_char  options[0];
} ipv6_hop_by_hop_t;

// Destination Options
typedef struct {
    u_char  next_header;
    u_char  hdr_ext_len;
    u_char  options[0];
} ipv6_dest_options_t;

// Routing
typedef struct {
    u_char  next_header;
    u_char  hdr_ext_len;
    u_char  routing_type;
    u_char  segments_left;
    u_char  data[0];
} ipv6_routing_t;

// Fragment
typedef struct {
    u_char  next_header;
    u_char  reserved;
    u_short frag_offset_res_m;
    u_int   id;
} ipv6_fragment_t;
#pragma pack(pop)

// API
void parse_ipv4(const u_char *data, int size);
void parse_ipv6(const u_char *data, int size);

#endif // IP_H
