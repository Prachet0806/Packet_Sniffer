/* One field list drives snapshots, checkpoints and database payloads. */
#define STATS_FIELDS(X)                                                                            \
    X(total_packets)                                                                               \
    X(total_bytes)                                                                                 \
    X(wire_bytes)                                                                                  \
    X(analyzed)                                                                                    \
    X(queue_drops)                                                                                 \
    X(allocation_drops)                                                                            \
    X(recording_errors)                                                                            \
    X(malformed)                                                                                   \
    X(truncated)                                                                                   \
    X(unsupported)                                                                                 \
    X(incomplete)                                                                                  \
    X(alert_drops)                                                                                 \
    X(state_evictions)                                                                             \
    X(ethernet)                                                                                    \
    X(ethernet_bytes)                                                                              \
    X(ipv4)                                                                                        \
    X(ipv4_bytes)                                                                                  \
    X(ipv6)                                                                                        \
    X(ipv6_bytes)                                                                                  \
    X(tcp)                                                                                         \
    X(tcp_bytes)                                                                                   \
    X(udp)                                                                                         \
    X(udp_bytes)                                                                                   \
    X(icmp)                                                                                        \
    X(icmp_bytes)                                                                                  \
    X(arp)                                                                                         \
    X(arp_bytes)                                                                                   \
    X(dns)                                                                                         \
    X(dns_bytes)                                                                                   \
    X(http)                                                                                        \
    X(http_bytes)                                                                                  \
    X(https)                                                                                       \
    X(https_bytes)                                                                                 \
    X(dhcp)                                                                                        \
    X(dhcp_bytes)
