// dhcp.h - DHCP protocol parsing
#ifndef DHCP_H
#define DHCP_H

#ifndef _WIN32
#include <sys/types.h>
#endif
#include <pcap.h>
#include <stdint.h>
#include <assert.h>

// DHCP message types (option 53)
#define DHCP_DISCOVER 1
#define DHCP_OFFER    2
#define DHCP_REQUEST  3
#define DHCP_DECLINE  4
#define DHCP_ACK      5
#define DHCP_NAK      6
#define DHCP_RELEASE  7
#define DHCP_INFORM   8

// DHCP ports
#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68

// DHCP header structure (fixed part, 240 bytes on the wire)
#ifdef _MSC_VER
#pragma pack(push, 1)
typedef struct {
    uint8_t  op;           // Message op code / message type (1 = BOOTREQUEST, 2 = BOOTREPLY)
    uint8_t  htype;        // Hardware address type (1 = Ethernet)
    uint8_t  hlen;         // Hardware address length (6 for MAC)
    uint8_t  hops;         // Client sets to zero, optionally used by relay agents
    uint32_t xid;          // Transaction ID, random number
    uint16_t secs;         // Seconds elapsed since client began process
    uint16_t flags;        // Flags (bit 15 = broadcast flag)
    uint32_t ciaddr;       // Client IP address (if client already has one)
    uint32_t yiaddr;       // 'Your' (client) IP address
    uint32_t siaddr;       // IP address of next server to use in bootstrap
    uint32_t giaddr;       // Relay agent IP address
    uint8_t  chaddr[16];   // Client hardware address (MAC address)
    uint8_t  sname[64];    // Optional server host name
    uint8_t  file[128];    // Boot file name
    uint32_t magic;        // Magic cookie (0x63825363)
} dhcp_header_t;
#pragma pack(pop)
#else
typedef struct {
    uint8_t  op;
    uint8_t  htype;
    uint8_t  hlen;
    uint8_t  hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t  chaddr[16];
    uint8_t  sname[64];
    uint8_t  file[128];
    uint32_t magic;
} __attribute__((packed)) dhcp_header_t;
#endif

// DHCP option structure
#ifdef _MSC_VER
#pragma pack(push, 1)
typedef struct {
    uint8_t code;
    uint8_t len;
    uint8_t data[1];
} dhcp_option_t;
#pragma pack(pop)
#else
typedef struct {
    uint8_t code;
    uint8_t len;
    uint8_t data[];
} __attribute__((packed)) dhcp_option_t;
#endif

// DHCPv6 ports
#define DHCPV6_SERVER_PORT 547
#define DHCPV6_CLIENT_PORT 546

// Function declarations
void parse_dhcp(const u_char *data, int size, const char *src_ip, const char *dst_ip,
                unsigned short src_port, unsigned short dst_port);
// Minimal DHCPv6 classifier (msg type + transaction ID; full option walk is future work)
void parse_dhcpv6(const u_char *data, int size, const char *src_ip, const char *dst_ip,
                  unsigned short src_port, unsigned short dst_port);

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L || defined(_MSC_VER) && _MSC_VER >= 1600
static_assert(sizeof(dhcp_header_t) == 240, "dhcp_header_t must be 240 bytes packed");
#endif

#endif // DHCP_H
