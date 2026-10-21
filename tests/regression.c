#include "stats.h"
#include "stats_fields.h"
#include "security.h"
#include "https.h"
#include "ip.h"
#include "udp.h"
#include "stream.h"
#include "util.h"
#include "logger.h"
#include <string.h>
#include <stdlib.h>
#define CHECK(x)                                                                                   \
    do {                                                                                           \
        if (!(x)) {                                                                                \
            fprintf(stderr, "CHECK failed line %d: %s\n", __LINE__, #x);                           \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)
int main(void) {
    log_init();
    current_log_level_int = LOG_ERROR;
    CHECK(stats_init(NULL) == 0);
    security_init();
    stats_capture(91, 120);
    stats_increment("ETH", 91);
    stats_increment("IPv4", 77);
    stats_increment("TCP", 57);
    stats_increment("HTTP", 37);
    ProtocolStats snap;
    stats_snapshot(&snap);
    CHECK(snap.total_packets == 1 && snap.total_bytes == 91 && snap.wire_bytes == 120 &&
          snap.http == 1);
    CHECK(stats_save_json("roundtrip.json") == 0);
    CHECK(stats_load_json("roundtrip.json") == 0);
    ProtocolStats loaded;
    stats_snapshot(&loaded);
    CHECK(!memcmp(&snap, &loaded, sizeof(snap)));
    JsonObject j;
    uint64_t value;
    CHECK(json_parse(&j, "{\"n\":18446744073709551615}") == 0);
    CHECK(json_u64(&j, json_find(&j, "n"), &value) == 0 && value == UINT64_MAX);
    CHECK(json_parse(&j, "{\"n\":18446744073709551616}") == 0);
    CHECK(json_u64(&j, json_find(&j, "n"), &value) != 0);
    CHECK(json_parse(&j, "{\"n\":1,\"n\":2}") != 0);
    CHECK(json_parse(&j, "{\"n\" 1}") != 0);
    CHECK(json_parse(&j, "{\"bpf\":\"tcp and (port 80 or port 443)\"}") == 0);
    char bpf[128];
    CHECK(json_string(&j, json_find(&j, "bpf"), bpf, sizeof(bpf)) == 0);
    unsigned char tls[49] = {22, 3, 3, 0, 44, 1, 0, 0, 44};
    tls[47] = 0;
    tls[48] = 4;
    parse_https(tls, sizeof(tls), "1", "2", 1, 443);
    for (int n = 0; n < 49; n++)
        parse_https(tls, n, "1", "2", 1, 443);
    unsigned char ip[40] = {0x45};
    ip[9] = 17;
    parse_ipv4(ip, sizeof(ip));
    stats_snapshot(&loaded);
    CHECK(loaded.udp == 0);
    unsigned char udp[20] = {0, 53, 0, 53, 0, 1};
    parse_udp(udp, sizeof(udp), "1", "2");
    stats_snapshot(&loaded);
    CHECK(loaded.dns == 0);
    security_set_context(1000000000, 1);
    for (int i = 0; i < 40; i++)
        security_tcp_syn("1.1.1.1", "2.2.2.2", 123, 80, 2);
    CHECK(security_alert_count() == 0);
    for (int i = 0; i < 20; i++)
        security_tcp_syn("1.1.1.1", "2.2.2.2", 123, (uint16_t)(100 + i), 2);
    CHECK(security_alert_count() == 1);
    security_arp(2, "1.1.1.1", "aa", "1.1.1.1");
    CHECK(security_alert_count() == 1);
    security_set_network(2);
    security_arp(2, "1.1.1.1", "bb", "1.1.1.1");
    CHECK(security_alert_count() == 1);
    security_set_network(1);
    security_arp(2, "1.1.1.1", "cc", "1.1.1.1");
    CHECK(security_alert_count() == 2);
    security_alert("quote\"", "a\\b", "c", "x\"\\y");
    char alerts[8192];
    CHECK(security_get_alerts(alerts, sizeof(alerts)) > 0);
    CHECK(strstr(alerts, "quote\\\""));
    CHECK(security_get_alerts(alerts, 16) < 0);
    unsigned char request[] = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    stats_snapshot(&snap);
    stream_feed(NULL, 0, "3", "4", 1000, 80, 99, 2);
    stream_feed(request + 10, (int)sizeof(request) - 1 - 10, "3", "4", 1000, 80, 110, 16);
    stream_feed(request, 10, "3", "4", 1000, 80, 100, 16);
    stream_feed(request, (int)sizeof(request) - 1, "3", "4", 1000, 80, 100, 16);
    stats_snapshot(&loaded);
    CHECK(loaded.http == snap.http + 1);
    /* A new connection on the same tuple must not inherit the old sequence window. */
    stream_feed(NULL, 0, "3", "4", 1000, 80, 9, 2);
    stream_feed(NULL, 0, "3", "4", 1000, 80, 9, 2);
    stream_feed(request, (int)sizeof(request) - 1, "3", "4", 1000, 80, 10, 16);
    stream_feed(request, (int)sizeof(request) - 1, "3", "4", 1000, 80, 10, 16);
    stats_snapshot(&loaded);
    CHECK(loaded.http == snap.http + 2);
    int alerts_before = security_alert_count();
    security_dns_name("src", "ordinarylonglabel.ordinarylonglabel.ordinarylonglabel.example", 1, 1,
                      0);
    CHECK(security_alert_count() == alerts_before);
    security_dns_name("src", "abcdefghijklmnopqrstuvwxyz0123456789ABCDEF.example", 1, 1, 0);
    CHECK(security_alert_count() == alerts_before + 1);
    unsigned char client[16] = {0};
    for (int i = 0; i < 50; i++)
        security_dhcp(1, client, 7, 0, 0);
    CHECK(security_alert_count() == alerts_before + 1);
    for (int i = 0; i < 32; i++) {
        client[0] = (unsigned char)(i + 1);
        security_dhcp(1, client, (uint32_t)(i + 100), 0, 0);
    }
    CHECK(security_alert_count() == alerts_before + 2);
    stream_cleanup();
    CHECK(stats_cleanup() == 0);
    security_cleanup();
    log_cleanup();
    puts("REGRESSION_OK");
    return 0;
}
