#include "sniffer.h"
#include "analyzer.h"
#include "stats.h"
#include "security.h"
#include "logger.h"
#include "util.h"
#include "stream.h"
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif
#define QUEUE_MAX 10000
static atomic_flag_t stop_flag;
static mutex_t control_cs;
static int control_ready, dlt = DLT_EN10MB, offline, running;
static char lifecycle[24] = "initializing", command[512];
static int command_pending, command_result;
static uint64_t last_packet, queue_bytes, queue_limit = 64 * 1024 * 1024;
static int queue_count;
#ifndef _WIN32
static volatile sig_atomic_t signal_stop;
static struct sigaction old_int, old_term;
#else
static BOOL WINAPI console_handler(DWORD event) {
    if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT || event == CTRL_CLOSE_EVENT) {
        flag_set(&stop_flag, 1);
        return TRUE;
    }
    return FALSE;
}
#endif
/* Capture alone owns pcap and services commands between nonblocking reads. */
typedef struct Packet {
    struct Packet *next;
    struct pcap_pkthdr header;
    unsigned char data[1];
} Packet;
static Packet *head, *tail;
static mutex_t queue_cs;
static int queue_shutdown;
int sniffer_init(void) {
    if (control_ready)
        return -1;
    mutex_init(&control_cs);
    control_ready = 1;
    const char *rp = getenv("SNIFFER_READ");
    offline = rp && *rp;
    flag_set(&stop_flag, 0);
    return 0;
}
void sniffer_cleanup(void) {
    if (control_ready) {
        mutex_destroy(&control_cs);
        control_ready = 0;
    }
}
int sniffer_datalink(void) { return dlt; }
int sniffer_is_offline(void) {
    if (!control_ready)
        return 0;
    mutex_lock(&control_cs);
    int v = offline;
    mutex_unlock(&control_cs);
    return v;
}
void sniffer_request_stop(void) { flag_set(&stop_flag, 1); }
static int stopped(void) {
#ifndef _WIN32
    if (signal_stop)
        return 1;
#endif
    return flag_get(&stop_flag);
}
int sniffer_apply_filter(const char *bpf) {
    if (!control_ready || !bpf || !*bpf || strlen(bpf) >= sizeof(command))
        return -1;
    mutex_lock(&control_cs);
    if (!running || offline || command_pending) {
        mutex_unlock(&control_cs);
        return -2;
    }
    strcpy(command, bpf);
    command_pending = 1;
    mutex_unlock(&control_cs);
    uint64_t end = monotonic_ms() + 1500;
    while (monotonic_ms() < end) {
        sleep_ms(5);
        mutex_lock(&control_cs);
        int pending = command_pending, rc = command_result;
        mutex_unlock(&control_cs);
        if (!pending)
            return rc;
    }
    /* The buffer remains owned by capture; timeout never frees command storage. */
    return -3;
}
int sniffer_health_json(char *out, int size) {
    if (!control_ready)
        return snprintf(out, (size_t)size, "{\"state\":\"uninitialized\"}");
    mutex_lock(&control_cs);
    int n = snprintf(out, (size_t)size,
                     "{\"state\":\"%s\",\"running\":%s,\"offline\":%s,\"last_packet_monotonic_ms\":"
                     "%llu,\"queue_packets\":%d,\"queue_bytes\":%llu}",
                     lifecycle, running ? "true" : "false", offline ? "true" : "false",
                     (unsigned long long)last_packet, queue_count, (unsigned long long)queue_bytes);
    mutex_unlock(&control_cs);
    return n;
}
static void state(const char *s, int active) {
    mutex_lock(&control_cs);
    snprintf(lifecycle, sizeof(lifecycle), "%s", s);
    running = active;
    if (!active) {
        command_result = -2;
        command_pending = 0;
    }
    mutex_unlock(&control_cs);
}
static int set_filter(pcap_t *h, const char *bpf) {
    struct bpf_program fp = {0};
    if (pcap_compile(h, &fp, bpf, 1, PCAP_NETMASK_UNKNOWN) < 0)
        return -1;
    int rc = pcap_setfilter(h, &fp);
    pcap_freecode(&fp);
    return rc;
}
static void service_command(pcap_t *h) {
    char bpf[512];
    mutex_lock(&control_cs);
    int pending = command_pending;
    if (pending)
        strcpy(bpf, command);
    mutex_unlock(&control_cs);
    if (pending) {
        int rc = set_filter(h, bpf);
        mutex_lock(&control_cs);
        command_result = rc;
        command_pending = 0;
        mutex_unlock(&control_cs);
    }
}
#ifndef _WIN32
static void signal_handler(int sig) {
    (void)sig;
    signal_stop = 1;
}
#endif
static int enqueue(const struct pcap_pkthdr *h, const unsigned char *data) {
    if (h->caplen > 262144) {
        stats_note("unsupported");
        stats_note("queue_drops");
        return -1;
    }
    size_t bytes = sizeof(Packet) + (h->caplen ? h->caplen - 1 : 0);
    for (;;) {
        mutex_lock(&queue_cs);
        mutex_lock(&control_cs);
        int full = queue_count >= QUEUE_MAX || queue_bytes + bytes > queue_limit;
        if (!full) {
            queue_count++;
            queue_bytes += bytes;
        }
        mutex_unlock(&control_cs);
        mutex_unlock(&queue_cs);
        if (!full)
            break;
        if (!offline || stopped()) {
            stats_note("queue_drops");
            return -1;
        }
        sleep_ms(1);
    }
    Packet *p = malloc(bytes);
    if (!p) {
        mutex_lock(&control_cs);
        queue_count--;
        queue_bytes -= bytes;
        mutex_unlock(&control_cs);
        stats_note("allocation_drops");
        return -1;
    }
    p->header = *h;
    p->next = NULL;
    if (h->caplen)
        memcpy(p->data, data, h->caplen);
    mutex_lock(&queue_cs);
    if (tail)
        tail->next = p;
    else
        head = p;
    tail = p;
    mutex_unlock(&queue_cs);
    return 0;
}
/* Recording has its own bounded queue so disk latency never blocks capture. */
static Packet *record_head, *record_tail;
static uint64_t record_bytes;
static int record_shutdown, record_started;
static thread_t record_thread;
static pcap_dumper_t *record_dumper;
static atomic_flag_t record_failed, record_discard;
static void record_enqueue(const struct pcap_pkthdr *h, const u_char *data) {
    size_t bytes = sizeof(Packet) + (h->caplen ? h->caplen - 1 : 0);
    mutex_lock(&queue_cs);
    if (h->caplen > 262144 || record_bytes + bytes > 32 * 1024 * 1024) {
        mutex_unlock(&queue_cs);
        stats_note("recording_errors");
        return;
    }
    record_bytes += bytes;
    mutex_unlock(&queue_cs);
    Packet *p = malloc(bytes);
    if (!p) {
        mutex_lock(&queue_cs);
        record_bytes -= bytes;
        mutex_unlock(&queue_cs);
        stats_note("recording_errors");
        return;
    }
    p->header = *h;
    p->next = NULL;
    if (h->caplen)
        memcpy(p->data, data, h->caplen);
    mutex_lock(&queue_cs);
    if (record_tail)
        record_tail->next = p;
    else
        record_head = p;
    record_tail = p;
    mutex_unlock(&queue_cs);
}
#ifdef _WIN32
static DWORD WINAPI recording_thread(LPVOID unused) {
#else
static void *recording_thread(void *unused) {
#endif
    (void)unused;
    for (;;) {
        mutex_lock(&queue_cs);
        Packet *p = record_head;
        int done = record_shutdown;
        if (p) {
            record_head = p->next;
            if (!record_head)
                record_tail = NULL;
            record_bytes -= sizeof(*p) + (p->header.caplen ? p->header.caplen - 1 : 0);
        }
        mutex_unlock(&queue_cs);
        if (!p) {
            if (done)
                break;
            sleep_ms(1);
            continue;
        }
        if (flag_get(&record_failed) || flag_get(&record_discard))
            stats_note("recording_errors");
        else {
            pcap_dump((u_char *)record_dumper, &p->header, p->data);
            if (pcap_dump_flush(record_dumper)) {
                stats_note("recording_errors");
                flag_set(&record_failed, 1);
                sniffer_request_stop();
            }
        }
        free(p);
    }
    return 0;
}
static void record_join(void) {
    if (!record_started)
        return;
    mutex_lock(&queue_cs);
    record_shutdown = 1;
    mutex_unlock(&queue_cs);
#ifdef _WIN32
    if (WaitForSingleObject(record_thread, 5000) == WAIT_TIMEOUT) {
        flag_set(&record_discard, 1);
        flag_set(&record_failed, 1);
        CancelSynchronousIo(record_thread);
    }
    WaitForSingleObject(record_thread, INFINITE);
    CloseHandle(record_thread);
#else
    pthread_join(record_thread, NULL);
#endif
    record_started = 0;
}
#ifdef _WIN32
static DWORD WINAPI analysis_thread(LPVOID unused) {
#else
static void *analysis_thread(void *unused) {
#endif
    (void)unused;
    for (;;) {
        mutex_lock(&queue_cs);
        Packet *p = head;
        int done = queue_shutdown;
        if (p) {
            head = p->next;
            if (!head)
                tail = NULL;
        }
        mutex_unlock(&queue_cs);
        if (!p) {
            if (done)
                break;
            sleep_ms(1);
            continue;
        }
        analyze_packet(&p->header, p->data);
        mutex_lock(&control_cs);
        queue_count--;
        queue_bytes -= sizeof(*p) + (p->header.caplen ? p->header.caplen - 1 : 0);
        mutex_unlock(&control_cs);
        free(p);
    }
    stream_cleanup();
    return 0;
}
static pcap_t *open_capture(char *err) {
    const char *rp = getenv("SNIFFER_READ");
    if (offline)
        return pcap_open_offline(rp, err);
    pcap_if_t *all = NULL;
    if (pcap_findalldevs(&all, err))
        return NULL;
    const char *iface = getenv("SNIFFER_IFACE");
    pcap_if_t *chosen = NULL;
    long index;
    int i = 0, matches = 0;
    if (iface) {
        int numeric = parse_integer(iface, 1, 100000, &index) == 0;
        if (!numeric && strspn(iface, "0123456789") == strlen(iface)) {
            snprintf(err, PCAP_ERRBUF_SIZE, "Invalid interface index");
            pcap_freealldevs(all);
            return NULL;
        }
        for (pcap_if_t *d = all; d; d = d->next) {
            i++;
            if (!numeric && !strcmp(d->name, iface)) {
                chosen = d;
                matches = 1;
                break;
            }
            if ((numeric && i == index) ||
                (!numeric &&
                 (strstr(d->name, iface) || (d->description && strstr(d->description, iface))))) {
                chosen = d;
                matches++;
            }
        }
    } else {
#ifdef _WIN32
        int interactive = _isatty(_fileno(stdin));
#else
        int interactive = isatty(fileno(stdin));
#endif
        if (interactive) {
            for (pcap_if_t *d = all; d; d = d->next)
                printf("%d. %s\n", ++i, d->name);
            char b[32];
            printf("Interface number: ");
            if (fgets(b, sizeof(b), stdin)) {
                b[strcspn(b, "\r\n")] = 0;
                if (!parse_integer(b, 1, i, &index)) {
                    i = 0;
                    for (pcap_if_t *d = all; d; d = d->next)
                        if (++i == index) {
                            chosen = d;
                            matches = 1;
                        }
                }
            }
        }
    }
    if (!chosen || matches != 1) {
        snprintf(err, PCAP_ERRBUF_SIZE,
                 "Interface missing or ambiguous; pass --iface with an exact name/index");
        pcap_freealldevs(all);
        return NULL;
    }
    long snap, timeout, promisc;
    if (env_integer("SNIFFER_SNAPLEN", 65536, 68, 262144, &snap) ||
        env_integer("SNIFFER_TIMEOUT_MS", 1000, 10, 60000, &timeout) ||
        env_integer("SNIFFER_PROMISC", 1, 0, 1, &promisc)) {
        pcap_freealldevs(all);
        return NULL;
    }
    pcap_t *h = pcap_open_live(chosen->name, (int)snap, (int)promisc, (int)timeout, err);
    pcap_freealldevs(all);
    if (h && pcap_setnonblock(h, 1, err)) {
        pcap_close(h);
        return NULL;
    }
    return h;
}
int start_sniffer(void) {
    if (!control_ready)
        return 1;
    char err[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *h = open_capture(err);
    if (!h) {
        LOG_ERROR_MSG("Capture open failed: %s\n", err);
        state("failed", 0);
        return 1;
    }
    dlt = pcap_datalink(h);
    int rc = 0;
    pcap_dumper_t *dump = NULL;
    const char *filter = getenv("SNIFFER_FILTER"), *write = getenv("SNIFFER_WRITE");
    if (filter && *filter && set_filter(h, filter)) {
        LOG_ERROR_MSG("Filter rejected: %s\n", pcap_geterr(h));
        pcap_close(h);
        state("failed", 0);
        return 1;
    }
    if (write && *write) {
        dump = pcap_dump_open(h, write);
        if (!dump) {
            LOG_ERROR_MSG("Cannot create recording\n");
            pcap_close(h);
            state("failed", 0);
            return 1;
        }
    }
    long limit;
    if (env_integer("SNIFFER_QUEUE_BYTES", 64 * 1024 * 1024, 262144, 1024 * 1024 * 1024, &limit)) {
        if (dump)
            pcap_dump_close(dump);
        pcap_close(h);
        return 1;
    }
    queue_limit = (uint64_t)limit;
    mutex_init(&queue_cs);
    queue_shutdown = 0;
    head = tail = NULL;
    queue_count = 0;
    queue_bytes = 0;
    record_head = record_tail = NULL;
    record_bytes = 0;
    record_shutdown = 0;
    record_started = 0;
    record_dumper = dump;
    flag_set(&record_failed, 0);
    flag_set(&record_discard, 0);
    if (dump) {
#ifdef _WIN32
        record_thread = CreateThread(NULL, 0, recording_thread, NULL, 0, NULL);
        if (!record_thread) {
            rc = 1;
            goto no_thread;
        }
#else
        if (pthread_create(&record_thread, NULL, recording_thread, NULL)) {
            rc = 1;
            goto no_thread;
        }
#endif
        record_started = 1;
    }
    thread_t thread;
#ifdef _WIN32
    thread = CreateThread(NULL, 0, analysis_thread, NULL, 0, NULL);
    if (!thread) {
        rc = 1;
        goto no_thread;
    }
    SetConsoleCtrlHandler(console_handler, TRUE);
#else
    if (pthread_create(&thread, NULL, analysis_thread, NULL)) {
        rc = 1;
        goto no_thread;
    }
    signal_stop = 0;
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = signal_handler;
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, &old_int);
    sigaction(SIGTERM, &action, &old_term);
#endif
    state("running", 1);
    LOG_INFO_SIMPLE("Capture started (DLT=%d, offline=%d)\n", dlt, offline);
    while (!stopped()) {
        service_command(h);
        struct pcap_pkthdr *header;
        const u_char *data;
        int n = pcap_next_ex(h, &header, &data);
        if (n == 0) {
            sleep_ms(5);
            continue;
        }
        if (n == -2)
            break;
        if (n < 0) {
            LOG_ERROR_MSG("Capture read failed: %s\n", pcap_geterr(h));
            rc = 1;
            break;
        }
        stats_capture_at(header->caplen, header->len,
                         (int64_t)header->ts.tv_sec * 1000000 + header->ts.tv_usec);
        mutex_lock(&control_cs);
        last_packet = monotonic_ms();
        mutex_unlock(&control_cs);
        if (dump)
            record_enqueue(header, data);
        enqueue(header, data);
    }
    state("stopping", 0);
    mutex_lock(&queue_cs);
    queue_shutdown = 1;
    mutex_unlock(&queue_cs);
#ifdef _WIN32
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    SetConsoleCtrlHandler(console_handler, FALSE);
#else
    pthread_join(thread, NULL);
    sigaction(SIGINT, &old_int, NULL);
    sigaction(SIGTERM, &old_term, NULL);
#endif
    if (!offline) {
        struct pcap_stat ps;
        if (!pcap_stats(h, &ps))
            LOG_INFO_SIMPLE("Kernel received=%u dropped=%u\n", ps.ps_recv, ps.ps_drop);
    }
no_thread:
    record_join();
    if (flag_get(&record_failed))
        rc = 1;
    mutex_destroy(&queue_cs);
    if (dump)
        pcap_dump_close(dump);
    pcap_close(h);
    state(rc ? "failed" : "stopped", 0);
    return rc;
}
