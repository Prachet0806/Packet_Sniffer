#include "https.h"
#include "stats.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// TLS record header format (simplified)
typedef struct {
    uint8_t content_type;
    uint16_t version;
    uint16_t length;
} tls_record_header_t;

static const char *tls_content_type(uint8_t type) {
    switch (type) {
        case 20: return "ChangeCipherSpec";
        case 21: return "Alert";
        case 22: return "Handshake";
        case 23: return "ApplicationData";
        default: return "Unknown";
    }
}

static const char *tls_version(uint16_t v) {
    switch (v) {
        case 0x0300: return "SSL 3.0";
        case 0x0301: return "TLS 1.0";
        case 0x0302: return "TLS 1.1";
        case 0x0303: return "TLS 1.2";
        case 0x0304: return "TLS 1.3";
        default: return "Unknown";
    }
}

void parse_https(const u_char *data, int size,
                 const char *src_ip, const char *dst_ip,
                 uint16_t sport, uint16_t dport) {
    if (size < 5) {
        printf("HTTPS: Truncated TLS record\n");
        return;
    }

    // Increment HTTPS stats
    stats_increment("HTTPS");

    tls_record_header_t hdr;
    hdr.content_type = data[0];
    hdr.version = (data[1] << 8) | data[2];
    hdr.length  = (data[3] << 8) | data[4];
    
    // Validate TLS record length against available data
    // TLS record header is 5 bytes, so payload starts at offset 5
    if (hdr.length > (size_t)(size - 5)) {
        printf("HTTPS: Warning - TLS record length (%u) exceeds available data (%d)\n", 
               hdr.length, size - 5);
        hdr.length = (size > 5) ? (size - 5) : 0;
    }

    printf("HTTPS: %s:%u -> %s:%u, TLS Record: %s, Version=%s, Length=%u\n",
           src_ip, sport, dst_ip, dport,
           tls_content_type(hdr.content_type),
           tls_version(hdr.version),
           hdr.length);

    // Future extension: parse TLS handshake for Server Name Indication (SNI)
}
