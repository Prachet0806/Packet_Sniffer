// security.c - rule-based analytics (SYN-scan, DNS-tunnel, ARP-spoof, DHCP-starvation, SNI)
#include "security.h"
#include "logger.h"
#include "os_compat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ALERT_RING 128
#define FLAP_TABLE 64
#define SYN_TABLE 64

typedef struct {
    char time_s[32];
    char type[32];
    char src[64];
    char dst[64];
    char detail[192];
} AlertEntry;

static AlertEntry ring[ALERT_RING];
static int ring_head = 0;
static int ring_count = 0;
static mutex_t sec_cs;
static int sec_ready = 0;

static void sec_lock_init(void) {
    if (!sec_ready) { mutex_init(&sec_cs); sec_ready = 1; }
}

void security_init(void) { sec_lock_init(); }

static void now_str(char *out, int n) {
    time_t t = time(NULL);
#if defined(_WIN32)
    struct tm tmv; localtime_s(&tmv, &t);
    strftime(out, (size_t)n, "%Y-%m-%dT%H:%M:%S", &tmv);
#else
    struct tm tmv; localtime_r(&t, &tmv);
    strftime(out, (size_t)n, "%Y-%m-%dT%H:%M:%S", &tmv);
#endif
}

void security_alert(const char *type, const char *src, const char *dst, const char *detail) {
    sec_lock_init();
    char ts[32] = {0};
    now_str(ts, sizeof(ts));
    char ctype[32] = {0}, csrc[64] = {0}, cdst[64] = {0}, cdet[192] = {0};
    if (type) { snprintf(ctype, sizeof(ctype), "%s", type); sanitize_printable(ctype, sizeof(ctype)); }
    if (src) { snprintf(csrc, sizeof(csrc), "%s", src); sanitize_printable(csrc, sizeof(csrc)); }
    if (dst) { snprintf(cdst, sizeof(cdst), "%s", dst); sanitize_printable(cdst, sizeof(cdst)); }
    if (detail) { snprintf(cdet, sizeof(cdet), "%s", detail); sanitize_printable(cdet, sizeof(cdet)); }

    mutex_lock(&sec_cs);
    AlertEntry *e = &ring[ring_head];
    snprintf(e->time_s, sizeof(e->time_s), "%s", ts);
    snprintf(e->type, sizeof(e->type), "%s", ctype);
    snprintf(e->src, sizeof(e->src), "%s", csrc);
    snprintf(e->dst, sizeof(e->dst), "%s", cdst);
    snprintf(e->detail, sizeof(e->detail), "%s", cdet);
    ring_head = (ring_head + 1) % ALERT_RING;
    if (ring_count < ALERT_RING) ring_count++;
    mutex_unlock(&sec_cs);

    char msg[512];
    snprintf(msg, sizeof(msg), "[ALERT] %s %s src=%s dst=%s %s\n",
             ts, ctype, csrc, cdst, cdet);
    log_emit_stderr(msg);
}

int security_alert_count(void) {
    if (!sec_ready) return 0;
    mutex_lock(&sec_cs);
    int n = ring_count;
    mutex_unlock(&sec_cs);
    return n;
}

// JSON array of alerts (newest last). Returns bytes written.
int security_get_alerts(char *out, int outlen) {
    if (!out || outlen <= 8) return 0;
    sec_lock_init();
    mutex_lock(&sec_cs);
    int pos = 0;
    pos += snprintf(out + pos, (size_t)(outlen - pos), "[");
    int start = (ring_head - ring_count + ALERT_RING * 2) % ALERT_RING;
    for (int i = 0; i < ring_count && pos < outlen - 256; i++) {
        AlertEntry *e = &ring[(start + i) % ALERT_RING];
        pos += snprintf(out + pos, (size_t)(outlen - pos),
            "%s{\"time\":\"%s\",\"type\":\"%s\",\"src\":\"%s\",\"dst\":\"%s\",\"detail\":\"%s\"}",
            i ? "," : "", e->time_s, e->type, e->src, e->dst, e->detail);
    }
    pos += snprintf(out + pos, (size_t)(outlen - pos), "]");
    mutex_unlock(&sec_cs);
    return pos;
}

// ---- SYN scan: N SYN-only packets from one src within window ----
typedef struct { char ip[64]; time_t win_start; int syn_only; int alerted; } SynEntry;
static SynEntry syns[SYN_TABLE];

void security_tcp_syn(const char *src_ip, const char *dst_ip,
                      uint16_t sport, uint16_t dport, unsigned char flags) {
    (void)sport; (void)dport;
    int is_syn_only = ((flags & 0x02) && !(flags & 0x10));
    if (!is_syn_only) return;
    if (!src_ip) return;
    time_t now = time(NULL);
    sec_lock_init();
    mutex_lock(&sec_cs);
    for (int i = 0; i < SYN_TABLE; i++) {
        if (syns[i].ip[0] && strcmp(syns[i].ip, src_ip) == 0) {
            if (now - syns[i].win_start > 60) { syns[i].win_start = now; syns[i].syn_only = 0; syns[i].alerted = 0; }
            syns[i].syn_only++;
            if (syns[i].syn_only >= 20 && !syns[i].alerted) {
                syns[i].alerted = 1;
                char d[96]; snprintf(d, sizeof(d), "SYN-only burst n=%d in 60s", syns[i].syn_only);
                mutex_unlock(&sec_cs);
                security_alert("syn-scan", src_ip, dst_ip ? dst_ip : "", d);
                return;
            }
            mutex_unlock(&sec_cs);
            return;
        }
    }
    for (int i = 0; i < SYN_TABLE; i++) {
        if (!syns[i].ip[0]) {
            snprintf(syns[i].ip, sizeof(syns[i].ip), "%s", src_ip);
            syns[i].win_start = now; syns[i].syn_only = 1; syns[i].alerted = 0;
            mutex_unlock(&sec_cs);
            return;
        }
    }
    // table full: evict slot 0
    snprintf(syns[0].ip, sizeof(syns[0].ip), "%s", src_ip);
    syns[0].win_start = now; syns[0].syn_only = 1; syns[0].alerted = 0;
    mutex_unlock(&sec_cs);
}

// ---- DNS tunnel heuristics ----
void security_dns_query(const char *src_ip, const char *dst_ip,
                        const unsigned char *data, int size) {
    (void)data;
    // Oversized DNS over UDP/TCP payload is tunnel-ish
    if (size > 512) {
        char d[96]; snprintf(d, sizeof(d), "large DNS payload %d bytes", size);
        security_alert("dns-tunnel", src_ip ? src_ip : "", dst_ip ? dst_ip : "", d);
    }
}

static double qname_entropy(const char *s) {
    int freq[256] = {0}; int n = 0;
    for (const char *p = s; *p; p++) { freq[(unsigned char)*p]++; n++; }
    if (!n) return 0;
    double e = 0;
    for (int i = 0; i < 256; i++) if (freq[i]) {
        double p = (double)freq[i] / n;
        double l = 0; double x = p;
        // log2 via ln approx: use log() if available
        // avoid libm dep: simple threshold on distinct chars instead
        (void)l; (void)x;
        e += -p * p; // placeholder (not real entropy, used with length checks)
    }
    return e;
}

void security_dns_name(const char *src_ip, const char *qname,
                       unsigned qtype, unsigned qdcount, unsigned ancount) {
    if (!qname) return;
    (void)qname_entropy(qname);
    size_t L = strlen(qname);
    int suspicious = 0;
    char reason[96] = {0};
    if (L > 50) { suspicious = 1; snprintf(reason, sizeof(reason), "long qname len=%zu", L); }
    else if (qtype == 16 || qtype == 10 || qtype == 41) { // TXT/NULL/OPT
        if (L > 30) { suspicious = 1; snprintf(reason, sizeof(reason), "qtype=%u with len=%zu", qtype, L); }
    } else if (qdcount > 5) { suspicious = 1; snprintf(reason, sizeof(reason), "qdcount=%u", qdcount); }
    else if (ancount > 20) { suspicious = 1; snprintf(reason, sizeof(reason), "ancount=%u", ancount); }
    else {
        // count labels / dashes: tunnel-ish if many labels or long label
        int labels = 1, maxlabel = 0, cur = 0;
        for (const char *p = qname; *p; p++) { if (*p == '.') { labels++; if (cur > maxlabel) maxlabel = cur; cur = 0; } else cur++; }
        if (cur > maxlabel) maxlabel = cur;
        if (labels > 6 || maxlabel > 32) { suspicious = 1; snprintf(reason, sizeof(reason), "labels=%d maxlabel=%d", labels, maxlabel); }
    }
    if (suspicious) security_alert("dns-tunnel", src_ip ? src_ip : "", "", reason);
}

// ---- ARP spoof: gratuitous / unsolicited reply / IP->MAC flap ----
typedef struct { char ip[32]; char mac[32]; time_t last; } ArpEntry;
static ArpEntry arps[FLAP_TABLE];

void security_arp(unsigned op, const char *sender_ip, const char *sender_mac,
                  const char *target_ip) {
    if (!sender_ip || !sender_mac) return;
    if (sender_ip[0] && target_ip && strcmp(sender_ip, target_ip) == 0) {
        char d[96]; snprintf(d, sizeof(d), "gratuitous ARP %s is %s", sender_ip, sender_mac);
        security_alert("arp-spoof", sender_ip, target_ip, d);
    }
    if (op == 2) {
        // unsolicited reply heuristic: broadcast target MAC ff:ff
        // (caller passes printable strings; check target MAC via sender? keep simple: track flap)
    }
    sec_lock_init();
    mutex_lock(&sec_cs);
    for (int i = 0; i < FLAP_TABLE; i++) {
        if (arps[i].ip[0] && strcmp(arps[i].ip, sender_ip) == 0) {
            if (strcmp(arps[i].mac, sender_mac) != 0) {
                char d[128]; snprintf(d, sizeof(d), "IP %s flap %s -> %s", sender_ip, arps[i].mac, sender_mac);
                mutex_unlock(&sec_cs);
                security_alert("arp-spoof", sender_ip, target_ip ? target_ip : "", d);
                mutex_lock(&sec_cs);
                snprintf(arps[i].mac, sizeof(arps[i].mac), "%s", sender_mac);
            }
            arps[i].last = time(NULL);
            mutex_unlock(&sec_cs);
            return;
        }
    }
    for (int i = 0; i < FLAP_TABLE; i++) {
        if (!arps[i].ip[0]) {
            snprintf(arps[i].ip, sizeof(arps[i].ip), "%s", sender_ip);
            snprintf(arps[i].mac, sizeof(arps[i].mac), "%s", sender_mac);
            arps[i].last = time(NULL);
            mutex_unlock(&sec_cs);
            return;
        }
    }
    mutex_unlock(&sec_cs);
}

// ---- DHCP starvation: DISCOVER burst ----
static time_t dhcp_win = 0;
static int dhcp_disc = 0;
static int dhcp_alerted = 0;

void security_dhcp(unsigned msg_type, const unsigned char *chaddr,
                   uint32_t xid, uint16_t secs, uint16_t flags) {
    (void)chaddr; (void)xid; (void)secs; (void)flags;
    if (msg_type != 1) return; // DISCOVER only
    time_t now = time(NULL);
    sec_lock_init();
    mutex_lock(&sec_cs);
    if (now - dhcp_win > 10) { dhcp_win = now; dhcp_disc = 0; dhcp_alerted = 0; }
    dhcp_disc++;
    if (dhcp_disc >= 10 && !dhcp_alerted) {
        dhcp_alerted = 1;
        char d[96]; snprintf(d, sizeof(d), "DISCOVER burst n=%d in 10s (starvation?)", dhcp_disc);
        mutex_unlock(&sec_cs);
        security_alert("dhcp-starvation", "", "", d);
        return;
    }
    mutex_unlock(&sec_cs);
}

void security_tls_sni(const char *src_ip, const char *dst_ip, const char *sni) {
    if (!sni || !sni[0]) return; // blind spot documented: ECH/TLS1.3 hide SNI
    size_t L = strlen(sni);
    if (L > 64) {
        char d[96]; snprintf(d, sizeof(d), "long SNI len=%zu", L);
        security_alert("tls-sni", src_ip ? src_ip : "", dst_ip ? dst_ip : "", d);
    }
}

// Peer context for DNS name hooks
static char g_peer_src[64] = {0};
static char g_peer_dst[64] = {0};
void security_set_peer(const char *src_ip, const char *dst_ip) {
    if (src_ip) { strncpy(g_peer_src, src_ip, sizeof(g_peer_src)-1); g_peer_src[sizeof(g_peer_src)-1]='\0'; }
    else g_peer_src[0]='\0';
    if (dst_ip) { strncpy(g_peer_dst, dst_ip, sizeof(g_peer_dst)-1); g_peer_dst[sizeof(g_peer_dst)-1]='\0'; }
    else g_peer_dst[0]='\0';
}
const char *security_peer_src(void) { return g_peer_src; }
