// Packet analysis implementation
#include "analyzer.h"
#include "ethernet.h"
#include "logger.h"
#include <stdio.h>

// Packet counter for periodic summaries
static unsigned long long packet_count = 0;

void analyze_packet(const struct pcap_pkthdr *header, const u_char *pkt_data) {
    packet_count++;
    
    // Only log every Nth packet in INFO mode to reduce console spam
    if (current_log_level < LOG_DEBUG) {
        if (packet_count % 1000 == 0) {
            LOG_INFO_MSG("Processed %llu packets...\n", packet_count);
        }
    } else {
        // Full per-packet logging in DEBUG mode
        LOG_DEBUG_SIMPLE("\n[+] Packet #%llu: length %d bytes (captured: %d bytes)\n", 
               packet_count, header->len, header->caplen);
    }
    
    parse_ethernet(pkt_data, header->caplen);
}
