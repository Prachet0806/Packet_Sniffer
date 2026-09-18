#ifndef SECURITY_H
#define SECURITY_H

#include <stdint.h>

// Rule-based security analytics (append-only, no parser output break).
// All functions are safe to call from analysis thread.
void security_init(void);
void security_alert(const char *type, const char *src, const char *dst, const char *detail);

// TCP SYN-scan hook: call after TCP validation. flags = TCP flags byte.
void security_tcp_syn(const char *src_ip, const char *dst_ip,
                      uint16_t sport, uint16_t dport, unsigned char flags);
// DNS hooks: call with full tuple before parse_dns() drops it.
void security_dns_query(const char *src_ip, const char *dst_ip,
                        const unsigned char *data, int size);
void security_dns_name(const char *src_ip, const char *qname,
                       unsigned qtype, unsigned qdcount, unsigned ancount);
// ARP hook: op = ntohs(operation), sender/target printable strings.
void security_arp(unsigned op, const char *sender_ip, const char *sender_mac,
                  const char *target_ip);
// DHCP hook: msg_type 0 if unknown, chaddr 6 bytes, xid host order.
void security_dhcp(unsigned msg_type, const unsigned char *chaddr,
                   uint32_t xid, uint16_t secs, uint16_t flags);
// TLS SNI hook: sni already sanitized, may be "" if absent.
void security_tls_sni(const char *src_ip, const char *dst_ip, const char *sni);
// Peer context for DNS (parse_dns drops tuple): set by UDP/TCP before call.
void security_set_peer(const char *src_ip, const char *dst_ip);
const char *security_peer_src(void);

// Persisted alerts sink info for API/Grafana.
int security_alert_count(void);
int security_get_alerts(char *out, int outlen);

#endif
