// Fuzz-ish smoke test: parsers must not crash on malformed input
#include <stdio.h>
#include <string.h>
#include "ethernet.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"
#include "dns.h"
#include "dhcp.h"
#include "arp.h"
#include "icmp.h"
#include "http.h"
#include "https.h"
#include "logger.h"
#include "stats.h"

int main(int argc, char **argv) {
    const char *out = (argc > 1 && argv[1][0]) ? argv[1] : "./smoke-stats.json";
    log_init();
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

    // DHCPv6 SOLICIT via UDP 546->547
    unsigned char u6[12] = {0x02,0x22, 0x02,0x23, 0,12, 0,0, 1,0x12,0x34,0x56};
    parse_udp(u6, sizeof(u6), "fe80::1", "ff02::1:2");

    // DHCPv4 DISCOVER with bad op must be rejected, not crash
    unsigned char dbad[244];
    memset(dbad, 0, sizeof(dbad));
    dbad[0]=9; // bad op
    parse_dhcp(dbad, sizeof(dbad), "0.0.0.0", "255.255.255.255", 68, 67);

    // TLS ClientHello with SNI=example.com (lengths must be exact)
    unsigned char ext[20] = {0,0, 0,16, 0,14, 0, 0,11,
        'e','x','a','m','p','l','e','.','c','o','m'};
    static unsigned char rec[128];
    memset(rec, 0, sizeof(rec));
    rec[0]=22; rec[1]=3; rec[2]=3;
    int ch_body = 2+32+1+2+2+1+1+2+20, ch_len = 4+ch_body;
    rec[3]=(ch_len>>8)&0xFF; rec[4]=ch_len&0xFF;
    unsigned char *ch = rec+5;
    ch[0]=1; ch[1]=(ch_body>>16)&0xFF; ch[2]=(ch_body>>8)&0xFF; ch[3]=ch_body&0xFF;
    ch[4]=3; ch[5]=3;
    int cp = 4+2+32;
    ch[cp++]=0;
    ch[cp++]=0; ch[cp++]=2; ch[cp++]=0; ch[cp++]=0x2F;
    ch[cp++]=1; ch[cp++]=0;
    ch[cp++]=(20>>8)&0xFF; ch[cp++]=20&0xFF;
    memcpy(ch+cp, ext, 20);
    parse_https(rec, 5+ch_len, "1.1.1.1", "2.2.2.2", 50000, 443);

    // ICMPv4 dest-unreach with embedded TCP flow
    unsigned char ic[8+20+8];
    memset(ic, 0, sizeof(ic));
    ic[0]=3; ic[1]=3;
    unsigned char *emb = ic+8;
    emb[0]=0x45; emb[8]=64; emb[9]=6;
    emb[12]=1; emb[13]=2; emb[14]=3; emb[15]=4;
    emb[16]=5; emb[17]=6; emb[18]=7; emb[19]=8;
    emb[20]=0x04; emb[21]=0xD2; emb[22]=0; emb[23]=80;
    parse_icmp(ic, sizeof(ic));

    int rc = stats_save_json(out);
    stats_cleanup();
    if (rc != 0) { fprintf(stderr, "smoke: stats_save_json(%s) failed\n", out); return 1; }
    printf("SMOKE_OK\n");
    return 0;
}
