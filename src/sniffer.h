// Packet sniffer functions
#ifndef SNIFFER_H
#define SNIFFER_H

void start_sniffer();
// Datalink type of the live capture (DLT_EN10MB, DLT_NULL, ...). Valid after open.
int sniffer_datalink(void);
// 1 when replaying --read file, 0 for live capture
int sniffer_is_offline(void);
// Apply BPF at runtime (live only). 0 ok, -1 bad filter, -2 offline/no handle.
int sniffer_apply_filter(const char *bpf);

#endif // SNIFFER_H
