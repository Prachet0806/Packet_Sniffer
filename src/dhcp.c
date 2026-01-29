// dhcp.c - DHCP protocol parsing implementation
#include "dhcp.h"
#include "stats.h"
#include "logger.h"
#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

// DHCP magic cookie
#define DHCP_MAGIC_COOKIE 0x63825363

// Common DHCP option codes
#define DHCP_OPT_PAD              0
#define DHCP_OPT_SUBNET_MASK      1
#define DHCP_OPT_ROUTER           3
#define DHCP_OPT_DNS_SERVER       6
#define DHCP_OPT_HOSTNAME         12
#define DHCP_OPT_REQUESTED_IP     50
#define DHCP_OPT_LEASE_TIME       51
#define DHCP_OPT_MESSAGE_TYPE     53
#define DHCP_OPT_SERVER_ID        54
#define DHCP_OPT_PARAM_REQ_LIST   55
#define DHCP_OPT_RENEWAL_TIME     58
#define DHCP_OPT_REBINDING_TIME   59
#define DHCP_OPT_CLIENT_ID        61
#define DHCP_OPT_END              255

// Get DHCP message type name
static const char* get_dhcp_message_type(uint8_t type) {
    switch (type) {
        case DHCP_DISCOVER: return "DISCOVER";
        case DHCP_OFFER:    return "OFFER";
        case DHCP_REQUEST:  return "REQUEST";
        case DHCP_DECLINE:  return "DECLINE";
        case DHCP_ACK:      return "ACK";
        case DHCP_NAK:      return "NAK";
        case DHCP_RELEASE:  return "RELEASE";
        case DHCP_INFORM:   return "INFORM";
        default:            return "UNKNOWN";
    }
}

// Get operation type name
static const char* get_dhcp_op_name(uint8_t op) {
    switch (op) {
        case 1: return "BOOTREQUEST";
        case 2: return "BOOTREPLY";
        default: return "UNKNOWN";
    }
}

// Parse DHCP options
static void parse_dhcp_options(const u_char *options, int options_len, 
                               uint8_t *msg_type, char *hostname, int hostname_size,
                               uint32_t *requested_ip, uint32_t *server_id) {
    int offset = 0;
    
    *msg_type = 0;
    hostname[0] = '\0';
    *requested_ip = 0;
    *server_id = 0;
    
    while (offset < options_len) {
        uint8_t code = options[offset];
        
        // End option
        if (code == DHCP_OPT_END) {
            break;
        }
        
        // Pad option (no length)
        if (code == DHCP_OPT_PAD) {
            offset++;
            continue;
        }
        
        // Check if we have enough space for length byte
        if (offset + 1 >= options_len) {
            LOG_WARN_SIMPLE("DHCP: Truncated option at offset %d\n", offset);
            break;
        }
        
        uint8_t len = options[offset + 1];
        
        // Validate option length
        if (offset + 2 + len > options_len) {
            LOG_WARN_SIMPLE("DHCP: Invalid option length %d at offset %d\n", len, offset);
            break;
        }
        
        const u_char *opt_data = &options[offset + 2];
        
        switch (code) {
            case DHCP_OPT_MESSAGE_TYPE:
                if (len == 1) {
                    *msg_type = opt_data[0];
                }
                break;
                
            case DHCP_OPT_HOSTNAME:
                if (len > 0 && len < hostname_size) {
                    memcpy(hostname, opt_data, len);
                    hostname[len] = '\0';
                }
                break;
                
            case DHCP_OPT_REQUESTED_IP:
                if (len == 4) {
                    memcpy(requested_ip, opt_data, 4);
                }
                break;
                
            case DHCP_OPT_SERVER_ID:
                if (len == 4) {
                    memcpy(server_id, opt_data, 4);
                }
                break;
                
            case DHCP_OPT_LEASE_TIME:
                if (len == 4) {
                    uint32_t lease_time;
                    memcpy(&lease_time, opt_data, 4);
                    lease_time = ntohl(lease_time);
                    LOG_DEBUG_SIMPLE("  Lease Time: %u seconds\n", lease_time);
                }
                break;
                
            case DHCP_OPT_SUBNET_MASK:
                if (len == 4) {
                    char mask[INET_ADDRSTRLEN];
                    struct in_addr addr;
                    memcpy(&addr.s_addr, opt_data, 4);
                    inet_ntop(AF_INET, &addr, mask, sizeof(mask));
                    LOG_DEBUG_SIMPLE("  Subnet Mask: %s\n", mask);
                }
                break;
                
            case DHCP_OPT_ROUTER:
                if (len >= 4) {
                    char router[INET_ADDRSTRLEN];
                    struct in_addr addr;
                    memcpy(&addr.s_addr, opt_data, 4);
                    inet_ntop(AF_INET, &addr, router, sizeof(router));
                    LOG_DEBUG_SIMPLE("  Router: %s\n", router);
                }
                break;
                
            case DHCP_OPT_DNS_SERVER:
                if (len >= 4) {
                    char dns[INET_ADDRSTRLEN];
                    struct in_addr addr;
                    memcpy(&addr.s_addr, opt_data, 4);
                    inet_ntop(AF_INET, &addr, dns, sizeof(dns));
                    LOG_DEBUG_SIMPLE("  DNS Server: %s\n", dns);
                }
                break;
        }
        
        offset += 2 + len;
    }
}

void parse_dhcp(const u_char *data, int size, const char *src_ip, const char *dst_ip,
                unsigned short src_port, unsigned short dst_port) {
    // Validate minimum size
    if (size < (int)sizeof(dhcp_header_t)) {
        LOG_WARN_SIMPLE("DHCP: Truncated header (size: %d, need: %zu)\n", 
                       size, sizeof(dhcp_header_t));
        return;
    }
    
    const dhcp_header_t *dhcp = (const dhcp_header_t *)data;
    
    // Verify magic cookie
    uint32_t magic = ntohl(dhcp->magic);
    if (magic != DHCP_MAGIC_COOKIE) {
        LOG_DEBUG_SIMPLE("DHCP: Invalid magic cookie 0x%08X (expected 0x%08X)\n", 
                        magic, DHCP_MAGIC_COOKIE);
        return;
    }
    
    // Increment stats
    stats_increment("DHCP");
    
    // Parse basic header info
    uint32_t xid = ntohl(dhcp->xid);
    uint16_t secs = ntohs(dhcp->secs);
    uint16_t flags = ntohs(dhcp->flags);
    int broadcast = (flags & 0x8000) != 0;
    
    // Convert IP addresses
    char ciaddr[INET_ADDRSTRLEN] = {0};
    char yiaddr[INET_ADDRSTRLEN] = {0};
    char siaddr[INET_ADDRSTRLEN] = {0};
    char giaddr[INET_ADDRSTRLEN] = {0};
    
    struct in_addr addr;
    
    if (dhcp->ciaddr != 0) {
        addr.s_addr = dhcp->ciaddr;
        inet_ntop(AF_INET, &addr, ciaddr, sizeof(ciaddr));
    }
    
    if (dhcp->yiaddr != 0) {
        addr.s_addr = dhcp->yiaddr;
        inet_ntop(AF_INET, &addr, yiaddr, sizeof(yiaddr));
    }
    
    if (dhcp->siaddr != 0) {
        addr.s_addr = dhcp->siaddr;
        inet_ntop(AF_INET, &addr, siaddr, sizeof(siaddr));
    }
    
    if (dhcp->giaddr != 0) {
        addr.s_addr = dhcp->giaddr;
        inet_ntop(AF_INET, &addr, giaddr, sizeof(giaddr));
    }
    
    // Parse options
    const u_char *options = data + sizeof(dhcp_header_t);
    int options_len = size - sizeof(dhcp_header_t);
    
    uint8_t msg_type = 0;
    char hostname[256] = {0};
    uint32_t requested_ip = 0;
    uint32_t server_id = 0;
    
    if (options_len > 0) {
        parse_dhcp_options(options, options_len, &msg_type, hostname, sizeof(hostname),
                          &requested_ip, &server_id);
    }
    
    // Print DHCP message info
    LOG_INFO_SIMPLE("DHCP: %s:%u -> %s:%u, Op=%s, Type=%s, XID=0x%08X\n",
           src_ip, src_port, dst_ip, dst_port,
           get_dhcp_op_name(dhcp->op),
           msg_type ? get_dhcp_message_type(msg_type) : "UNKNOWN",
           xid);
    
    // Print additional details in DEBUG mode
    LOG_DEBUG_SIMPLE("  Hardware: Type=%u, Len=%u, Hops=%u\n", 
           dhcp->htype, dhcp->hlen, dhcp->hops);
    
    LOG_DEBUG_SIMPLE("  Flags: 0x%04X %s\n", flags, broadcast ? "(Broadcast)" : "");
    LOG_DEBUG_SIMPLE("  Elapsed: %u seconds\n", secs);
    
    // Print MAC address
    if (dhcp->hlen <= 16) {
        LOG_DEBUG_SIMPLE("  Client MAC: ");
        for (int i = 0; i < dhcp->hlen && i < 16; i++) {
            LOG_DEBUG_SIMPLE("%02X%s", dhcp->chaddr[i], i < dhcp->hlen - 1 ? ":" : "");
        }
        LOG_DEBUG_SIMPLE("\n");
    }
    
    // Print IP addresses if present
    if (ciaddr[0]) LOG_DEBUG_SIMPLE("  Client IP: %s\n", ciaddr);
    if (yiaddr[0]) LOG_DEBUG_SIMPLE("  Your IP: %s\n", yiaddr);
    if (siaddr[0]) LOG_DEBUG_SIMPLE("  Server IP: %s\n", siaddr);
    if (giaddr[0]) LOG_DEBUG_SIMPLE("  Gateway IP: %s\n", giaddr);
    
    // Print hostname if present
    if (hostname[0]) {
        LOG_DEBUG_SIMPLE("  Hostname: %s\n", hostname);
    }
    
    // Print requested IP if present
    if (requested_ip != 0) {
        addr.s_addr = requested_ip;
        char req_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, req_ip, sizeof(req_ip));
        LOG_DEBUG_SIMPLE("  Requested IP: %s\n", req_ip);
    }
    
    // Print server ID if present
    if (server_id != 0) {
        addr.s_addr = server_id;
        char srv_id[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, srv_id, sizeof(srv_id));
        LOG_DEBUG_SIMPLE("  Server ID: %s\n", srv_id);
    }
}
