#ifndef SNIFFER_H
#define SNIFFER_H
#include <stdint.h>
int sniffer_init(void);
void sniffer_cleanup(void);
int start_sniffer(void);
int sniffer_datalink(void);
int sniffer_is_offline(void);
int sniffer_apply_filter(const char *bpf);
void sniffer_request_stop(void);
int sniffer_health_json(char *out, int size);
#endif
