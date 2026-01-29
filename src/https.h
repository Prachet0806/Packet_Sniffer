#ifndef HTTPS_H
#define HTTPS_H

#include <winsock2.h>
#include <stdint.h>  // for uint16_t

#ifndef u_char
typedef unsigned char u_char;
#endif

// Parse HTTPS/TLS traffic
void parse_https(const u_char *data, int size,
                 const char *src_ip, const char *dst_ip,
                 uint16_t sport, uint16_t dport);
#endif // HTTPS_H
