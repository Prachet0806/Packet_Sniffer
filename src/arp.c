// ARP packet parsing
#include "arp.h"
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>

// IP address formatting
static void format_ip(u_int ip_addr, char *buffer, int size) {
    struct in_addr addr;
    addr.s_addr = ip_addr;
    if (inet_ntop(AF_INET, &addr, buffer, size) == NULL) {
        snprintf(buffer, size, "Invalid");
    }
}

// MAC address formatting
static void format_mac(const u_char *mac, char *buffer) {
    snprintf(buffer, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void parse_arp(const u_char *data, int size) {
    if (size < (int)sizeof(arp_header_t)) {
        printf("ARP: Truncated header (got %d, need %d)\n",
               size, (int)sizeof(arp_header_t));
        return;
    }
    const arp_header_t *arp = (const arp_header_t *)data;

    // Validate packet
    if (ntohs(arp->hardware_type) != 1) {
        printf("ARP: Unsupported hardware type %u\n", ntohs(arp->hardware_type));
        return;
    }
    if (ntohs(arp->protocol_type) != 0x0800) {
        printf("ARP: Unsupported protocol type 0x%04X\n", ntohs(arp->protocol_type));
        return;
    }

    // Format addresses
    char sender_mac[18], target_mac[18];
    char sender_ip[16], target_ip[16];

    format_mac(arp->sender_mac, sender_mac);
    format_mac(arp->target_mac, target_mac);
    format_ip(arp->sender_ip, sender_ip, sizeof(sender_ip));
    format_ip(arp->target_ip, target_ip, sizeof(target_ip));

    // Operation type
    u_short op = ntohs(arp->operation);
    const char *op_name;
    switch (op) {
        case 1:  op_name = "ARP Request"; break;
        case 2:  op_name = "ARP Reply"; break;
        case 3:  op_name = "RARP Request"; break;
        case 4:  op_name = "RARP Reply"; break;
        default: op_name = "Unknown"; break;
    }

    // Display packet info
    printf("ARP: %s\n", op_name);
    printf("     Sender: %s (%s)\n", sender_ip, sender_mac);

    if (op == 1) {
        printf("     Target: %s (Broadcast)\n", target_ip);
    } else {
        printf("     Target: %s (%s)\n", target_ip, target_mac);
    }

    // Packet details
    printf("     Hardware Type: Ethernet (0x%04X)\n", ntohs(arp->hardware_type));
    printf("     Protocol Type: IPv4 (0x%04X)\n", ntohs(arp->protocol_type));
    printf("     Hardware Size: %u bytes\n", arp->hardware_size);
    printf("     Protocol Size: %u bytes\n", arp->protocol_size);
}
