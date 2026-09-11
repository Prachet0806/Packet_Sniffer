// Fuzz-ish smoke test: parsers must not crash on malformed input
#include <stdio.h>
#include <string.h>
#include "ethernet.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"
#include "dns.h"
#include "arp.h"
#include "icmp.h"
#include "http.h"
#include "https.h"
#include "stats.h"

int main(void) {
    stats_init(NULL);
    unsigned char buf[512];
    memset(buf, 0xC0, sizeof(buf));

    // Truncated ethernet
    parse_ethernet(buf, 5);
    // VLAN-tagged IPv4 stub
    unsigned char vlan[] = {
        0,1,2,3,4,5, 6,7,8,9,10,11, 0x81,0x00, 0x00,0x64, 0x08,0x00,
        0x45,0x00,0x00,0x14,0,0,0,0,64,6,0,0, 1,2,3,4, 5,6,7,8
    };
    parse_ethernet(vlan, sizeof(vlan));

    // IPv4 non-first fragment (offset=8) must skip transport
    unsigned char ipfrag[40];
    memset(ipfrag, 0, sizeof(ipfrag));
    ipfrag[0]=0x45; ipfrag[8]=64; ipfrag[9]=6;
    ipfrag[6]=0x20; ipfrag[7]=0x01; // MF + offset
    parse_ipv4(ipfrag, sizeof(ipfrag));

    // DNS compression loop: pointer to self
    unsigned char dns[32];
    memset(dns, 0, sizeof(dns));
    dns[0]=0x12; dns[1]=0x34; dns[2]=0x01; dns[3]=0x00;
    dns[4]=0x00; dns[5]=0x01; dns[6]=0x00; dns[7]=0x00;
    dns[8]=0x00; dns[9]=0x00; dns[10]=0x00; dns[11]=0x00;
    dns[12]=0xC0; dns[13]=0x0C; // pointer to 12 (self)
    parse_dns(dns, sizeof(dns));

    // DNS valid query for google.com
    unsigned char dns2[] = {
        0x12,0x34, 0x01,0x00, 0x00,0x01, 0,0, 0,0, 0,0,
        6,'g','o','o','g','l','e', 3,'c','o','m', 0,
        0,1, 0,1
    };
    parse_dns(dns2, sizeof(dns2));

    // HTTP with embedded NUL before Host (must not OOB)
    unsigned char http[] = {'G','E','T',' ','/',0,'X','X','H','o','s','t',':',' ','a',0};
    parse_http(http, sizeof(http), "1.1.1.1", "2.2.2.2", 1234, 80);

    // TLS multi-record + truncated
    unsigned char tls[] = {22,3,3,0,5, 1,2,3, 23,3,3,0,2, 9,9};
    parse_https(tls, sizeof(tls), "1.1.1.1", "2.2.2.2", 1234, 443);
    parse_https(tls, 3, "1.1.1.1", "2.2.2.2", 1234, 443);

    // TCP with HTTP payload
    unsigned char tcp[64];
    memset(tcp, 0, sizeof(tcp));
    tcp[0]=0; tcp[1]=80; tcp[2]=0x30; tcp[3]=0x39;
    tcp[12]=0x50; tcp[13]=0x18;
    memcpy(tcp+20, "GET / HTTP/1.0\r\nHost: x\r\n\r\n", 26);
    parse_tcp(tcp, 20+26, "1.1.1.1", "2.2.2.2");

    stats_save_json("C:/Users/prach/AppData/Local/Temp/smoke-stats.json");
    stats_cleanup();
    printf("SMOKE_OK\n");
    return 0;
}
