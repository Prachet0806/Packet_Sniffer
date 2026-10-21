#include "security.h"
#include "stats.h"
#include "logger.h"
#include "util.h"
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#define RING 128
#define TABLE 64
static mutex_t cs;
static int initialized, head, count;
static int64_t packet_us;
static uint32_t network;
static char peer[64];
typedef struct {
    char time[40], type[32], src[64], dst[64], detail[192];
} Alert;
static Alert ring[RING];
typedef struct {
    char dst[64];
    uint16_t port;
} Destination;
typedef struct {
    char ip[64];
    uint32_t net;
    int64_t start, last;
    int count, alerted;
    Destination seen[64];
} Syn;
static Syn syns[TABLE];
typedef struct {
    char ip[32], mac[32];
    uint32_t net;
    int64_t last;
} Arp;
static Arp arps[TABLE];
typedef struct {
    unsigned char mac[16];
    uint32_t xid, net;
    int64_t time;
} Discover;
static Discover discoveries[128];
static int disc_next;
static int64_t disc_alert;
void security_init(void) {
    mutex_init(&cs);
    initialized = 1;
    head = count = 0;
    packet_us = 0;
    network = 0;
    memset(syns, 0, sizeof(syns));
    memset(arps, 0, sizeof(arps));
    memset(discoveries, 0, sizeof(discoveries));
    disc_next = 0;
    disc_alert = 0;
}
void security_cleanup(void) {
    if (initialized) {
        mutex_destroy(&cs);
        initialized = 0;
    }
}
void security_set_context(int64_t t, uint32_t n) {
    packet_us = t;
    network = n;
}
void security_set_network(uint32_t n) { network = n; }
int64_t security_time_us(void) { return packet_us; }
uint32_t security_context_id(void) { return network; }
void security_set_peer(const char *s, const char *d) {
    (void)d;
    snprintf(peer, sizeof(peer), "%s", s ? s : "");
}
const char *security_peer_src(void) { return peer; }
static void timestamp(char *b, size_t n) {
    time_t t = packet_us ? (time_t)(packet_us / 1000000) : time(NULL);
    struct tm v;
#ifdef _WIN32
    gmtime_s(&v, &t);
#else
    gmtime_r(&t, &v);
#endif
    strftime(b, n, "%Y-%m-%dT%H:%M:%SZ", &v);
}
void security_alert(const char *type, const char *src, const char *dst, const char *detail) {
    if (!initialized)
        return;
    Alert a;
    timestamp(a.time, sizeof(a.time));
    snprintf(a.type, sizeof(a.type), "%s", type ? type : "");
    snprintf(a.src, sizeof(a.src), "%s", src ? src : "");
    snprintf(a.dst, sizeof(a.dst), "%s", dst ? dst : "");
    snprintf(a.detail, sizeof(a.detail), "%s", detail ? detail : "");
    sanitize_printable(a.type, sizeof(a.type));
    sanitize_printable(a.src, sizeof(a.src));
    sanitize_printable(a.dst, sizeof(a.dst));
    sanitize_printable(a.detail, sizeof(a.detail));
    mutex_lock(&cs);
    ring[head] = a;
    head = (head + 1) % RING;
    if (count < RING)
        count++;
    mutex_unlock(&cs);
    stats_queue_alert(a.time, a.type, a.src, a.dst, a.detail);
    LOG_WARN_MSG("[ALERT] %s %s src=%s dst=%s %s\n", a.time, a.type, a.src, a.dst, a.detail);
}
int security_alert_count(void) {
    if (!initialized)
        return 0;
    mutex_lock(&cs);
    int n = count;
    mutex_unlock(&cs);
    return n;
}
int security_get_alert_page(char *out, int cap, unsigned offset, unsigned limit) {
    if (!out || cap < 3 || !initialized)
        return -1;
    Alert copy[RING];
    int n;
    mutex_lock(&cs);
    n = count;
    for (int i = 0; i < n; i++)
        copy[i] = ring[(head - count + RING + i) % RING];
    mutex_unlock(&cs);
    size_t p = 0;
    out[p++] = '[';
    /* Prefer recent records when the caller's bounded response cannot hold the ring. */
    for (int i = (int)offset; i < n && (unsigned)i < offset + limit; i++) {
        char q[5][1200];
        const char *v[] = {copy[i].time, copy[i].type, copy[i].src, copy[i].dst, copy[i].detail};
        for (int k = 0; k < 5; k++)
            if (json_quote(q[k], sizeof(q[k]), v[k]) < 0)
                return -1;
        char row[2048];
        int r = snprintf(row, sizeof(row),
                         "%s{\"time\":%s,\"type\":%s,\"src\":%s,\"dst\":%s,\"detail\":%s,"
                         "\"confidence\":\"heuristic\"}",
                         i > (int)offset ? "," : "", q[0], q[1], q[2], q[3], q[4]);
        if (r < 0 || (size_t)r >= sizeof(row) || p + (size_t)r + 2 > (size_t)cap)
            return -1;
        memcpy(out + p, row, (size_t)r);
        p += (size_t)r;
    }
    out[p++] = ']';
    out[p] = 0;
    return (int)p;
}
int security_get_alerts(char *out, int cap) { return security_get_alert_page(out, cap, 0, RING); }
void security_tcp_syn(const char *src, const char *dst, uint16_t sp, uint16_t dp,
                      unsigned char flags) {
    (void)sp;
    if (!src || !dst || !(flags & 2) || (flags & 16))
        return;
    int64_t now = packet_us;
    Syn *entry = NULL, *slot = &syns[0];
    for (int i = 0; i < TABLE; i++) {
        Syn *a = &syns[i];
        if (a->ip[0] && a->net == network && !strcmp(a->ip, src))
            entry = a;
        if (!a->ip[0] || a->last < slot->last)
            slot = a;
    }
    if (!entry) {
        entry = slot;
        if (entry->ip[0])
            stats_note("state_evictions");
        memset(entry, 0, sizeof(*entry));
        snprintf(entry->ip, sizeof(entry->ip), "%s", src);
        entry->net = network;
        entry->start = now;
    }
    if (now < entry->start || now - entry->start > 60000000) {
        entry->count = 0;
        entry->alerted = 0;
        entry->start = now;
    }
    entry->last = now;
    for (int i = 0; i < entry->count; i++)
        if (entry->seen[i].port == dp && !strcmp(entry->seen[i].dst, dst))
            return;
    if (entry->count < 64) {
        Destination *d = &entry->seen[entry->count++];
        d->port = dp;
        snprintf(d->dst, sizeof(d->dst), "%s", dst);
    }
    long threshold;
    if (env_integer("SNIFFER_SYN_THRESHOLD", 20, 2, 64, &threshold))
        threshold = 20;
    if (entry->count >= threshold && !entry->alerted) {
        entry->alerted = 1;
        char d[96];
        snprintf(d, sizeof(d), "%d distinct destination/port pairs within 60s", entry->count);
        security_alert("syn-scan", src, dst, d);
    }
}
void security_dns_query(const char *src, const char *dst, const unsigned char *data, int size) {
    (void)src;
    (void)dst;
    (void)data;
    (void)size; /* Size alone is not attack evidence (EDNS and TCP permit large messages). */
}
void security_dns_name(const char *src, const char *name, unsigned type, unsigned questions,
                       unsigned answers) {
    (void)type;
    (void)answers;
    if (!name)
        return;
    const char *longest = name;
    size_t max = 0, current = 0;
    const char *start = name;
    for (const char *p = name;; p++) {
        if (*p == '.' || !*p) {
            if (current > max) {
                max = current;
                longest = start;
            }
            current = 0;
            start = p + 1;
            if (!*p)
                break;
        } else
            current++;
    }
    unsigned freq[256] = {0};
    for (size_t i = 0; i < max; i++)
        freq[(unsigned char)longest[i]]++;
    double entropy = 0;
    for (int i = 0; i < 256; i++)
        if (freq[i]) {
            double p = (double)freq[i] / (double)max;
            entropy -= p * log(p) / log(2.0);
        }
    if ((max >= 40 && entropy > 3.8) || questions > 32) {
        char d[96];
        snprintf(d, sizeof(d), "label length=%zu entropy=%.2f questions=%u", max, entropy,
                 questions);
        security_alert("dns-anomaly", src, "", d);
    }
}
void security_arp(unsigned op, const char *ip, const char *mac, const char *target) {
    if (!ip || !mac || !strcmp(ip, "0.0.0.0") || (op != 1 && op != 2))
        return;
    Arp *entry = NULL, *slot = &arps[0];
    int64_t now = packet_us;
    for (int i = 0; i < TABLE; i++) {
        Arp *a = &arps[i];
        if (a->ip[0] && a->net == network && !strcmp(a->ip, ip))
            entry = a;
        if (!a->ip[0] || a->last < slot->last)
            slot = a;
    }
    if (!entry) {
        entry = slot;
        if (entry->ip[0])
            stats_note("state_evictions");
        memset(entry, 0, sizeof(*entry));
        snprintf(entry->ip, sizeof(entry->ip), "%s", ip);
        entry->net = network;
    }
    if (entry->mac[0] && now >= entry->last && now - entry->last < 300000000 &&
        strcmp(entry->mac, mac) && op == 2) {
        char d[128];
        snprintf(d, sizeof(d), "mapping conflict %s -> %s (network=%u)", entry->mac, mac, network);
        security_alert("arp-conflict", ip, target, d);
    }
    snprintf(entry->mac, sizeof(entry->mac), "%s", mac);
    entry->last = now;
}
void security_dhcp(unsigned type, const unsigned char *mac, uint32_t xid, uint16_t secs,
                   uint16_t flags) {
    (void)secs;
    (void)flags;
    if (type != 1)
        return;
    int64_t now = packet_us;
    int discoveries_count = 0;
    for (int i = 0; i < 128; i++) {
        Discover *a = &discoveries[i];
        if (a->time && a->net == network && now >= a->time && now - a->time <= 10000000) {
            if (a->xid == xid && !memcmp(a->mac, mac, 16))
                return;
            discoveries_count++;
        }
    }
    Discover *d = &discoveries[disc_next++ % 128];
    memcpy(d->mac, mac, 16);
    d->xid = xid;
    d->net = network;
    d->time = now;
    long threshold;
    if (env_integer("SNIFFER_DHCP_THRESHOLD", 32, 2, 128, &threshold))
        threshold = 32;
    if (discoveries_count + 1 >= threshold && (now < disc_alert || now - disc_alert > 10000000)) {
        disc_alert = now;
        char msg[96];
        snprintf(msg, sizeof(msg), "%d distinct client transactions within 10s",
                 discoveries_count + 1);
        security_alert("dhcp-burst", "", "", msg);
    }
}
void security_tls_sni(const char *src, const char *dst, const char *sni) {
    if (sni && strlen(sni) > 200)
        security_alert("tls-sni-anomaly", src, dst, "unusually long server name; heuristic only");
}
