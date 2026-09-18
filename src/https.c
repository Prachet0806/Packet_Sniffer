#include "https.h"
#include "stats.h"
#include "logger.h"
#include "security.h"
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

// Bounded ClientHello SNI (server_name ext 0) extractor.
// hs = handshake message bytes, hslen = handshake length field.
// Returns 1 and fills sni_out when present, 0 otherwise. Prints SNI or nothing.
static int parse_client_hello_sni(const u_char *hs, int hslen, char *sni_out, int sni_len) {
    if (sni_out && sni_len > 0) sni_out[0] = '\0';
    // Handshake header: type(1) len(3) + ClientHello: ver(2) random(32)
    if (hslen < 4 + 2 + 32 + 1) return 0;
    unsigned msg_len = ((unsigned)hs[1] << 16) | ((unsigned)hs[2] << 8) | hs[3];
    // TLS handshake message length is 24-bit (max 16MB). Check for overflow.
    if (msg_len > 0xFFFFFF) return 0;
    if (msg_len > (unsigned)hslen) msg_len = (unsigned)hslen; // clamp to captured
    int hs_end = 4 + (int)msg_len;
    int p = 4 + 2 + 32;
    // session_id
    if (p + 1 > hs_end) return 0;
    int sid_len = hs[p++];
    if (sid_len > 32 || p + sid_len + 2 > hs_end) return 0;
    p += sid_len;
    // cipher_suites
    unsigned cs_len = ((unsigned)hs[p] << 8) | hs[p+1];
    p += 2;
    if (p + (int)cs_len + 1 > hs_end) return 0;
    p += cs_len;
    // compression_methods
    int cm_len = hs[p++];
    if (p + cm_len + 2 > hs_end) return 0;
    p += cm_len;
    // extensions
    unsigned ext_total = ((unsigned)hs[p] << 8) | hs[p+1];
    p += 2;
    if (p + (int)ext_total > hs_end) return 0;
    int ext_end = p + ext_total;
    while (p + 4 <= ext_end) {
        unsigned ext_type = ((unsigned)hs[p] << 8) | hs[p+1];
        unsigned ext_len = ((unsigned)hs[p+2] << 8) | hs[p+3];
        p += 4;
        if (p + (int)ext_len > ext_end) return 0;
        if (ext_type == 0 && ext_len >= 2) {
            unsigned list_len = ((unsigned)hs[p] << 8) | hs[p+1];
            int q = p + 2;
            if (q + (int)list_len <= p + (int)ext_len && list_len >= 3 && hs[q] == 0) {
                unsigned name_len = ((unsigned)hs[q+1] << 8) | hs[q+2];
                if (q + 3 + (int)name_len <= p + (int)ext_len && name_len < 253 && name_len > 0) {
                    char sni[254];
                    memcpy(sni, hs + q + 3, name_len);
                    sni[name_len] = '\0';
                    sanitize_printable(sni, sizeof(sni));
                    printf("HTTPS:   SNI=%s\n", sni);
                    if (sni_out && sni_len > 0) {
                        strncpy(sni_out, sni, (size_t)(sni_len - 1));
                        sni_out[sni_len - 1] = '\0';
                    }
                    return 1;
                }
            }
        }
        p += ext_len;
    }
    return 0;
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
        // ClientHello SNI: first record only (documented ECH/TLS1.3 blind spot)
        if (rec == 0 && ct == 22 && len >= 4 && data[off+5] == 1) {
            char sni[254] = {0};
            if (parse_client_hello_sni(data + off + 5, len, sni, sizeof(sni)) && sni[0])
                security_tls_sni(src_ip, dst_ip, sni);
        }
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
