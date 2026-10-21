#include "stream.h"
#include "http.h"
#include "https.h"
#include "dns.h"
#include "security.h"
#include "stats.h"
#include "os_compat.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#define FLOWS 64
#define WINDOW 65536
/* Analysis-thread-owned directional windows. First observed overlaps win; conflicting overlap
 * retires the flow. */
typedef struct {
    int used, kind, saw_syn;
    char src[64], dst[64];
    uint16_t sport, dport;
    uint32_t next, context, syn_seq;
    int64_t last;
    unsigned char *data, *present, *handshake;
    size_t hslen;
} Flow;
static Flow flows[FLOWS];
static void retire(Flow *f) {
    free(f->data);
    free(f->present);
    free(f->handshake);
    memset(f, 0, sizeof(*f));
}
void stream_cleanup(void) {
    for (int i = 0; i < FLOWS; i++)
        retire(&flows[i]);
}
static int find_header(const unsigned char *p, int n) {
    for (int i = 0; i + 4 <= n; i++)
        if (!memcmp(p + i, "\r\n\r\n", 4))
            return i + 4;
    return 0;
}
static int http_length(const unsigned char *p, int n, int header) {
    int content = 0, seen = 0;
    for (int i = 0; i < header;) {
        int e = i;
        while (e + 1 < header && !(p[e] == '\r' && p[e + 1] == '\n'))
            e++;
        if (e - i >= 15 && !strncasecmp_compat((const char *)p + i, "Content-Length:", 15)) {
            if (seen++)
                return -1;
            int j = i + 15;
            while (j < e && (p[j] == ' ' || p[j] == '\t'))
                j++;
            int value = 0, digits = 0;
            while (j < e && p[j] >= '0' && p[j] <= '9') {
                if (value > WINDOW / 10)
                    return -1;
                value = value * 10 + p[j++] - '0';
                digits++;
            }
            while (j < e && (p[j] == ' ' || p[j] == '\t'))
                j++;
            if (!digits || j != e || value > WINDOW - header)
                return -1;
            content = value;
        }
        if (e - i >= 18 && !strncasecmp_compat((const char *)p + i, "Transfer-Encoding:", 18))
            return -1;
        i = e + 2;
    }
    /* Close-delimited HTTP responses cannot be split into messages safely. */
    if (n >= 5 && !memcmp(p, "HTTP/", 5) && !seen) {
        if (n < 12)
            return -1;
        int status = (p[9] - '0') * 100 + (p[10] - '0') * 10 + p[11] - '0';
        if (!(status < 200 || status == 204 || status == 304))
            return -1;
    }
    return header + content;
}
static int messages(Flow *f, int n) {
    int used = 0;
    while (used < n) {
        unsigned char *p = f->data + used;
        int remain = n - used, length = 0;
        if (!f->kind) {
            if (f->sport == 53 || f->dport == 53)
                f->kind = 1;
            else if (f->sport == 443 || f->dport == 443 || f->sport == 8443 || f->dport == 8443)
                f->kind = 2;
            else if (f->sport == 80 || f->dport == 80 || f->sport == 8080 || f->dport == 8080 ||
                     f->sport == 8000 || f->dport == 8000)
                f->kind = 3;
            else if (remain >= 5 && p[0] >= 20 && p[0] <= 24 && p[1] == 3)
                f->kind = 2;
            else if (remain >= 5 &&
                     (!memcmp(p, "GET ", 4) || !memcmp(p, "POST ", 5) || !memcmp(p, "HTTP/", 5)))
                f->kind = 3;
            else {
                if (remain >= 16)
                    return -1;
                break;
            }
        }
        if (f->kind == 1) {
            if (remain < 2)
                break;
            length = 2 + ((int)p[0] << 8) + p[1];
            if (length < 14 || length > WINDOW)
                return -1;
            if (length > remain)
                break;
            security_set_peer(f->src, f->dst);
            security_dns_query(f->src, f->dst, p + 2, length - 2);
            parse_dns(p + 2, length - 2);
        } else if (f->kind == 2) {
            if (remain < 5)
                break;
            length = 5 + ((int)p[3] << 8) + p[4];
            if (length > WINDOW || p[0] < 20 || p[0] > 24 || p[1] != 3)
                return -1;
            if (length > remain)
                break;
            if (p[0] == 22) {
                int payload = length - 5;
                if (f->hslen + (size_t)payload > WINDOW)
                    return -1;
                memcpy(f->handshake + f->hslen, p + 5, (size_t)payload);
                f->hslen += (size_t)payload;
                while (f->hslen >= 4) {
                    size_t hlen = 4 + ((size_t)f->handshake[1] << 16) +
                                  ((size_t)f->handshake[2] << 8) + f->handshake[3];
                    if (hlen > WINDOW - 5)
                        return -1;
                    if (hlen > f->hslen)
                        break;
                    unsigned char *record = malloc(hlen + 5);
                    if (!record) {
                        stats_note("allocation_drops");
                        return -1;
                    }
                    record[0] = 22;
                    record[1] = 3;
                    record[2] = p[2];
                    record[3] = (unsigned char)(hlen >> 8);
                    record[4] = (unsigned char)hlen;
                    memcpy(record + 5, f->handshake, hlen);
                    parse_https(record, (int)hlen + 5, f->src, f->dst, f->sport, f->dport);
                    free(record);
                    f->hslen -= hlen;
                    memmove(f->handshake, f->handshake + hlen, f->hslen);
                }
            } else
                parse_https(p, length, f->src, f->dst, f->sport, f->dport);
        } else {
            int header = find_header(p, remain);
            if (!header)
                break;
            length = http_length(p, remain, header);
            if (length < 0)
                return -1;
            if (length > remain)
                break;
            parse_http(p, length, f->src, f->dst, f->sport, f->dport);
        }
        used += length;
    }
    return used;
}
void stream_feed(const unsigned char *p, int n, const char *src, const char *dst, uint16_t sp,
                 uint16_t dp, uint32_t seq, unsigned flags) {
    int64_t now = security_time_us();
    Flow *f = NULL, *slot = &flows[0];
    uint32_t context = security_context_id();
    for (int i = 0; i < FLOWS; i++) {
        Flow *a = &flows[i];
        if (a->used && now - a->last > 120000000) {
            if (a->hslen)
                stats_note("incomplete");
            retire(a);
        }
        if (a->used && a->context == context && a->sport == sp && a->dport == dp &&
            !strcmp(a->src, src) && !strcmp(a->dst, dst))
            f = a;
        if (!a->used || a->last < slot->last)
            slot = a;
    }
    if (flags & 4) {
        if (f)
            retire(f);
        return;
    }
    /* A fresh handshake can reuse a tuple before the old window expires. A
     * retransmission of the same SYN must retain the current window. */
    if (f && (flags & 2) && (!f->saw_syn || f->syn_seq != seq)) {
        retire(f);
        slot = f;
        f = NULL;
    }
    if (!f) {
        if (n == 0 && !(flags & 2))
            return;
        f = slot;
        if (f->used) {
            stats_note("state_evictions");
            retire(f);
        }
        f->data = malloc(WINDOW);
        f->present = calloc(WINDOW, 1);
        f->handshake = malloc(WINDOW);
        if (!f->data || !f->present || !f->handshake) {
            retire(f);
            stats_note("allocation_drops");
            return;
        }
        f->used = 1;
        f->context = context;
        strcpy(f->src, src);
        strcpy(f->dst, dst);
        f->sport = sp;
        f->dport = dp;
        f->saw_syn = !!(flags & 2);
        f->syn_seq = seq;
        f->next = seq + ((flags & 2) ? 1 : 0);
    }
    f->last = now;
    seq += ((flags & 2) ? 1 : 0);
    int32_t offset = (int32_t)(seq - f->next);
    if (offset < 0) {
        uint32_t skip = (uint32_t)(-(int64_t)offset);
        if (skip >= (uint32_t)n)
            return;
        p += skip;
        n -= (int)skip;
        offset = 0;
    }
    if ((uint32_t)offset + (uint32_t)n > WINDOW) {
        stats_note("incomplete");
        retire(f);
        return;
    }
    for (int i = 0; i < n; i++) {
        int k = offset + i;
        if (f->present[k] && f->data[k] != p[i]) {
            stats_note("malformed");
            retire(f);
            return;
        }
        f->data[k] = p[i];
        f->present[k] = 1;
    }
    int contiguous = 0;
    while (contiguous < WINDOW && f->present[contiguous])
        contiguous++;
    int consumed = messages(f, contiguous);
    if (consumed < 0) {
        stats_note("unsupported");
        retire(f);
        return;
    }
    if (consumed) {
        memmove(f->data, f->data + consumed, (size_t)(WINDOW - consumed));
        memmove(f->present, f->present + consumed, (size_t)(WINDOW - consumed));
        memset(f->present + WINDOW - consumed, 0, (size_t)consumed);
        f->next += (uint32_t)consumed;
    }
    if ((flags & 1) && seq + (uint32_t)n == f->next) {
        if (f->hslen)
            stats_note("incomplete");
        retire(f);
    }
}
