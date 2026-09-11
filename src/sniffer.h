// Packet sniffer functions
#ifndef SNIFFER_H
#define SNIFFER_H

void start_sniffer();
// Datalink type of the live capture (DLT_EN10MB, DLT_NULL, ...). Valid after open.
int sniffer_datalink(void);

#endif // SNIFFER_H
