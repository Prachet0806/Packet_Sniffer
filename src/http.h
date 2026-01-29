#ifndef HTTP_H
#define HTTP_H

#include <pcap.h>

// Parse an HTTP payload carried inside TCP
// src_ip/dst_ip are for logging context
void parse_http(const u_char *data, int size,
                const char *src_ip, const char *dst_ip,
                unsigned short src_port, unsigned short dst_port);

#endif // HTTP_H
