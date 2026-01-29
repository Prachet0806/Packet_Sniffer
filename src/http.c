#include "http.h"
#include "stats.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#ifdef _WIN32
#include <windows.h>  // For _strnicmp on Windows
#endif

#ifndef u_char
typedef unsigned char u_char;
#endif

// Helper: extract a line from payload (not null-terminated by default)
static void extract_line(const char *payload, int size, char *line, int maxlen) {
    if (size < 0 || maxlen < 1) {
        line[0] = '\0';
        return;
    }
    
    int i = 0;
    int max_copy = (size < maxlen - 1) ? size : (maxlen - 1);
    
    while (i < max_copy) {
        if (payload[i] == '\r' || payload[i] == '\n') break;
        line[i] = payload[i];
        i++;
    }
    line[i] = '\0';
}

// MSVC-compatible case-insensitive substring search
static const char *strcasestr_msvc(const char *haystack, const char *needle) {
    int needle_len = (int)strlen(needle);
    for (; *haystack; haystack++) {
        if (_strnicmp(haystack, needle, needle_len) == 0)
            return haystack;
    }
    return NULL;
}

void parse_http(const u_char *data, int size,
                const char *src_ip, const char *dst_ip,
                unsigned short src_port, unsigned short dst_port) {

    if (size <= 0) return;

    // Increment HTTP stats
    stats_increment("HTTP");

    // Extract first line (request or response line)
    char line[256];
    extract_line((const char *)data, size, line, sizeof(line));

    printf("[HTTP] %s:%u -> %s:%u | %s\n",
           src_ip, src_port, dst_ip, dst_port, line);

    // Look for Host header (case-insensitive)
    const char *host_ptr = strcasestr_msvc((const char *)data, "Host:");
    if (host_ptr) {
        // Validate host_ptr is within data bounds
        int host_offset = host_ptr - (const char *)data;
        if (host_offset >= 0 && host_offset < size) {
            char host_line[256];
            int remaining = size - host_offset;
            if (remaining > 0) {
                extract_line(host_ptr, remaining, host_line, sizeof(host_line));
                printf("[HTTP]   %s\n", host_line);
            }
        }
    }
}
