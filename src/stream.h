#ifndef STREAM_H
#define STREAM_H
#include <stdint.h>
void stream_feed(const unsigned char *data, int size, const char *src, const char *dst,
                 uint16_t sport, uint16_t dport, uint32_t sequence, unsigned flags);
void stream_cleanup(void);
#endif
