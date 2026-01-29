// DNS packet parsing
#ifndef DNS_H
#define DNS_H

#include <pcap.h>

#pragma pack(push, 1)
// DNS header
typedef struct {
    u_short transaction_id;
    u_short flags;
    u_short questions;
    u_short answer_rrs;
    u_short authority_rrs;
    u_short additional_rrs;
} dns_header_t;
#pragma pack(pop)

// DNS record types
#define DNS_TYPE_A      1
#define DNS_TYPE_NS     2
#define DNS_TYPE_CNAME  5
#define DNS_TYPE_SOA    6
#define DNS_TYPE_PTR    12
#define DNS_TYPE_MX     15
#define DNS_TYPE_TXT    16
#define DNS_TYPE_AAAA   28
#define DNS_TYPE_SRV    33
#define DNS_TYPE_OPT    41

// DNS classes
#define DNS_CLASS_IN    1

// DNS Flags bit masks
#define DNS_FLAG_QR     0x8000  // Query/Response
#define DNS_FLAG_AA     0x0400  // Authoritative Answer
#define DNS_FLAG_TC     0x0200  // Truncated
#define DNS_FLAG_RD     0x0100  // Recursion Desired
#define DNS_FLAG_RA     0x0080  // Recursion Available
#define DNS_FLAG_AD     0x0020  // Authentic Data
#define DNS_FLAG_CD     0x0010  // Checking Disabled

// DNS response codes
#define DNS_RCODE_NO_ERROR    0
#define DNS_RCODE_FORMAT_ERR  1
#define DNS_RCODE_SERVER_FAIL 2
#define DNS_RCODE_NAME_ERR    3
#define DNS_RCODE_NOT_IMPL    4
#define DNS_RCODE_REFUSED     5

// API
void parse_dns(const u_char *data, int size);

#endif // DNS_H
