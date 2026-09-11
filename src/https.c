#include "https.h"
#include "stats.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static const char *tls_content_type(uint8_t type) {
    switch (type) {
        case 20: return "ChangeCipherSpec";
        case 21: return "Alert";
        case 22: return "Handshake";
        case 23: return "ApplicationData";
        case 24: return "Heartbeat";
        default: return "Unknown";
    }
}

static const char *tls_version(uint16_t v) {
    switch (v) {
        case 0x0300: return "SSL 3.0";
        case 0x0301: return "TLS 1.0";
        case 0x0302: return "TLS 1.1";
        case 0x0303: return "TLS 1.2-or-1.3-wire";
        case 0x0304: return "TLS 1.3-inner";
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

    stats_increment("HTTPS", (uint32_t)size);

    // Parse possibly multiple coalesced TLS records in one TCP segment
    int off = 0;
    int rec = 0;
    while (off + 5 <= size && rec < 8) {
        uint8_t ct = data[off];
        uint16_t ver = ((uint16_t)data[off+1] << 8) | data[off+2];
        uint16_t len = ((uint16_t)data[off+3] << 8) | data[off+4];
        if (ct < 20 || ct > 24) {
            if (rec == 0) printf("HTTPS: not TLS (ct=%u)\n", ct);
            break;
        }
        int avail = size - off - 5;
        printf("HTTPS: %s:%u -> %s:%u, TLS Record: %s, Version=%s, Length=%u%s\n",
               src_ip, sport, dst_ip, dport,
               tls_content_type(ct), tls_version(ver), len,
               (int)len > avail ? " (truncated)" : "");
        if ((int)len > avail) break;
        off += 5 + len;
        rec++;
        // Only print first + count for brevity
        if (rec == 1 && off < size) {
            printf("HTTPS: ... +%d more bytes in segment\n", size - off);
            break;
        }
    }

    // Note: TLS 1.3 uses legacy 0x0303 on the wire; true version is in
    // ClientHello.supported_versions extension (encrypted afterwards).
}
