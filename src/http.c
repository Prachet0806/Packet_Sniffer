#include "http.h"
#include "stats.h"
#include "os_compat.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

// Helper: extract a line from payload (not null-terminated by default)
static void extract_line(const char *payload, int size, char *line, int maxlen) {
    int i = 0;
    while (i < size && i < maxlen - 1) {
        if (payload[i] == '\r' || payload[i] == '\n') break;
        // Replace non-printables to keep logs sane
        unsigned char c = (unsigned char)payload[i];
        line[i] = (c >= 32 && c < 127) ? (char)c : '.';
        i++;
    }
    line[i] = '\0';
}

// Bounded case-insensitive memory search (binary-safe, no OOB read)
static const u_char *memmem_nocase(const u_char *hay, int haylen,
                                   const char *needle, int needlelen) {
    if (needlelen <= 0 || haylen < needlelen) return NULL;
    for (int i = 0; i + needlelen <= haylen; i++) {
        if (strncasecmp_compat((const char *)(hay + i), needle, needlelen) == 0)
            return hay + i;
    }
    return NULL;
}

void parse_http(const u_char *data, int size,
                const char *src_ip, const char *dst_ip,
                unsigned short src_port, unsigned short dst_port) {

    if (size <= 0) return;

    // Increment HTTP stats (with byte length)
    stats_increment("HTTP", (uint32_t)(size > 0 ? size : 0));

    // Extract first line (request or response line)
    char line[256];
    extract_line((const char *)data, size, line, sizeof(line));

    printf("[HTTP] %s:%u -> %s:%u | %s\n",
           src_ip, src_port, dst_ip, dst_port, line);

    // Look for Host header (case-insensitive, bounded)
    const u_char *host_ptr = memmem_nocase(data, size, "Host:", 5);
    if (host_ptr) {
        int remain = size - (int)(host_ptr - data);
        char host_line[256];
        extract_line((const char *)host_ptr, remain, host_line, sizeof(host_line));
        printf("[HTTP]   %s\n", host_line);
    }
}
