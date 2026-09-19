// Multi-threaded packet sniffer (cross-platform, bounded queue, clean shutdown)
#include "sniffer.h"
#include "analyzer.h"
#include "os_compat.h"
#include "stats.h"
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>

#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#ifdef _MSC_VER
#pragma comment(lib, "iphlpapi.lib")
#endif
#else
#include <unistd.h>
#include <time.h>
#endif

#define QUEUE_MAX 10000

// Thread-safe queue
typedef struct PacketNode {
    struct pcap_pkthdr *header;
    u_char *data;
    struct PacketNode *next;
} PacketNode;

typedef struct {
    PacketNode *head;
    PacketNode *tail;
    mutex_t cs;
    cond_t cv;
    int count;
    int dropped;
    int shutdown;
} PacketQueue;

static PacketQueue queue;
static pcap_t *g_handle = NULL;
static int g_stop = 0;
static mutex_t g_stop_mutex;
static int g_verbose = 0;
static int g_dlt = DLT_EN10MB;
static int g_offline = 0;

static inline int get_g_stop(void) {
    int val;
    mutex_lock(&g_stop_mutex);
    val = g_stop;
    mutex_unlock(&g_stop_mutex);
    return val;
}

static inline void set_g_stop(int val) {
    mutex_lock(&g_stop_mutex);
    g_stop = val;
    mutex_unlock(&g_stop_mutex);
}

int sniffer_datalink(void) { return g_dlt; }
int sniffer_is_offline(void) { return g_offline; }
int sniffer_apply_filter(const char *bpf) {
    if (!bpf || !bpf[0]) return -1;
    if (g_offline || !g_handle) return -2; // live only
    struct bpf_program fp;
    if (pcap_compile(g_handle, &fp, bpf, 1, PCAP_NETMASK_UNKNOWN) == -1) return -1;
    int rc = pcap_setfilter(g_handle, &fp);
    pcap_freecode(&fp);
    return rc;
}

void queue_init(PacketQueue *q) {
    q->head = q->tail = NULL;
    q->count = 0;
    q->dropped = 0;
    q->shutdown = 0;
    mutex_init(&q->cs);
    cond_init(&q->cv);
    mutex_init(&g_stop_mutex);
    set_g_stop(0);
}

void queue_shutdown(PacketQueue *q) {
    mutex_lock(&q->cs);
    q->shutdown = 1;
#ifdef _WIN32
    WakeAllConditionVariable(&q->cv);
#else
    pthread_cond_broadcast(&q->cv);
#endif
    mutex_unlock(&q->cs);
}

void queue_destroy(PacketQueue *q) {
    mutex_lock(&q->cs);
    PacketNode *n = q->head;
    q->head = q->tail = NULL;
    q->count = 0;
    mutex_unlock(&q->cs);
    while (n) {
        PacketNode *nx = n->next;
        free(n->header);
        free(n->data);
        free(n);
        n = nx;
    }
    mutex_destroy(&q->cs);
}

// Returns 0 on success, -1 if dropped (full / alloc fail / shutting down)
int queue_push(PacketQueue *q, const struct pcap_pkthdr *header, const u_char *data) {
    if (get_g_stop() || q->shutdown) return -1;
    // Use caplen (actually captured), never len (wire length)
    bpf_u_int32 caplen = header->caplen;
    if (caplen == 0) return -1;
    if (caplen > 262144) caplen = 262144; // sanity cap

    PacketNode *node = (PacketNode *)malloc(sizeof(PacketNode));
    if (!node) return -1;
    node->header = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
    if (!node->header) { free(node); return -1; }
    memcpy(node->header, header, sizeof(struct pcap_pkthdr));
    node->header->caplen = caplen;
    // Clamp len display to caplen if snaplen truncated
    node->data = (u_char *)malloc(caplen ? caplen : 1);
    if (!node->data) { free(node->header); free(node); return -1; }
    memcpy(node->data, data, caplen);
    node->next = NULL;

    mutex_lock(&q->cs);
    if (q->shutdown || q->count >= QUEUE_MAX) {
        q->dropped++;
        mutex_unlock(&q->cs);
        free(node->header);
        free(node->data);
        free(node);
        return -1;
    }
    if (q->tail) q->tail->next = node;
    else q->head = node;
    q->tail = node;
    q->count++;
    int c = q->count;
    mutex_unlock(&q->cs);
#ifdef _WIN32
    WakeConditionVariable(&q->cv);
#else
    pthread_cond_signal(&q->cv);
#endif
    if (g_verbose) printf("[Queue] pushed, size=%d\n", c);
    return 0;
}

PacketNode* queue_pop(PacketQueue *q) {
    mutex_lock(&q->cs);
    for (;;) {
        if (q->head) break;
        if (q->shutdown || get_g_stop()) { mutex_unlock(&q->cs); return NULL; }
#ifdef _WIN32
        SleepConditionVariableCS(&q->cv, &q->cs, 500);
#else
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += 500 * 1000000L;
        if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
        pthread_cond_timedwait(&q->cv, &q->cs, &ts);
#endif
    }
    PacketNode *node = q->head;
    q->head = node->next;
    if (!q->head) q->tail = NULL;
    q->count--;
    int c = q->count;
    mutex_unlock(&q->cs);
    if (g_verbose) printf("[Queue] popped, size=%d\n", c);
    return node;
}

// MAC helper (Windows only; POSIX prints Unknown)
static void print_mac(const char *guid) {
#ifdef _WIN32
    ULONG buflen = 0;
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
    // First call to get required buffer size
    if (GetAdaptersAddresses(AF_UNSPEC, flags, NULL, NULL, &buflen) != ERROR_BUFFER_OVERFLOW) {
        printf(" (MAC: Unknown)");
        return;
    }
    IP_ADAPTER_ADDRESSES *info = (IP_ADAPTER_ADDRESSES *)malloc(buflen);
    if (!info) { printf(" (MAC: Unknown)"); return; }
    if (GetAdaptersAddresses(AF_UNSPEC, flags, NULL, info, &buflen) != ERROR_SUCCESS) {
        printf(" (MAC: Unknown)");
        free(info);
        return;
    }
    for (IP_ADAPTER_ADDRESSES *p = info; p; p = p->Next) {
        // guid looks like \Device\NPF_{GUID}; AdapterName is {GUID}
        // Convert adapter name to GUID format for comparison
        char adapter_guid[256];
        int guid_len = snprintf(adapter_guid, sizeof(adapter_guid), "{%S}", p->AdapterName);
        if (guid_len > 0 && strstr(guid, adapter_guid)) {
            if (p->PhysicalAddressLength == 6) {
                printf(" (MAC: %02X:%02X:%02X:%02X:%02X:%02X)",
                       p->PhysicalAddress[0], p->PhysicalAddress[1], p->PhysicalAddress[2],
                       p->PhysicalAddress[3], p->PhysicalAddress[4], p->PhysicalAddress[5]);
            } else {
                printf(" (MAC: Unknown)");
            }
            free(info);
            return;
        }
    }
    free(info);
    printf(" (MAC: Unknown)");
#else
    (void)guid;
    printf(" (MAC: n/a)");
#endif
}

// Packet capture handler (user cookie = pcap_dumper_t* or NULL)
static void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    if (get_g_stop()) return;
    if (g_verbose) printf("[Capture] caplen=%u len=%u\n", header->caplen, header->len);
    if (param) pcap_dump(param, header, pkt_data);
    if (queue_push(&queue, header, pkt_data) != 0 && g_verbose)
        printf("[Capture] packet dropped (queue full/alloc fail)\n");
}

// Analysis thread
#ifdef _WIN32
static DWORD WINAPI analysis_thread(LPVOID param) {
    (void)param;
    for (;;) {
        PacketNode *node = queue_pop(&queue);
        if (!node) break; // shutdown
        analyze_packet(node->header, node->data);
        free(node->header);
        free(node->data);
        free(node);
    }
    return 0;
}
#else
static void *analysis_thread(void *param) {
    (void)param;
    for (;;) {
        PacketNode *node = queue_pop(&queue);
        if (!node) break;
        analyze_packet(node->header, node->data);
        free(node->header);
        free(node->data);
        free(node);
    }
    return NULL;
}
#endif

static void request_stop(void) {
    set_g_stop(1);
    queue_shutdown(&queue);
    if (g_handle) pcap_breakloop(g_handle);
}

#ifdef _WIN32
static BOOL WINAPI console_handler(DWORD ev) {
    if (ev == CTRL_C_EVENT || ev == CTRL_CLOSE_EVENT || ev == CTRL_BREAK_EVENT || 
        ev == CTRL_LOGOFF_EVENT || ev == CTRL_SHUTDOWN_EVENT) { 
        request_stop(); return TRUE; 
    }
    return FALSE;
}
#else
static void sigint_handler(int sig) { (void)sig; request_stop(); }
static void sigterm_handler(int sig) { (void)sig; request_stop(); }
#endif

static int pick_device(pcap_if_t *alldevs, int n, int wanted) {
    (void)alldevs;
    if (wanted >= 1 && wanted <= n) return wanted;
    return -1;
}

// Sniffer (keeps old signature; env vars allow non-interactive/Docker use)
void start_sniffer() {
    const char *env_v = getenv("SNIFFER_VERBOSE");
    if (env_v && env_v[0] == '1') g_verbose = 1;
    const char *env_iface = getenv("SNIFFER_IFACE"); // 1-based index or name substring
    const char *env_filter = getenv("SNIFFER_FILTER");
    const char *read_path = getenv("SNIFFER_READ"); // offline replay input
    const char *write_path = getenv("SNIFFER_WRITE");
    int is_offline = (read_path && read_path[0]) ? 1 : 0;

    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *adhandle = NULL;
    char devname[512] = {0};
    mutex_init(&g_stop_mutex);
    set_g_stop(0);

    // Capture options (live only; ignored in --read mode)
    int snaplen = 65536;
    int promisc = 1;
    int timeout_ms = 1000;
    const char *e;
    if ((e = getenv("SNIFFER_SNAPLEN")) && atoi(e) >= 68 && atoi(e) <= 262144)
        snaplen = atoi(e);
    if ((e = getenv("SNIFFER_PROMISC")) && (e[0] == '0' || e[0] == 'n' || e[0] == 'N'))
        promisc = 0;
    if ((e = getenv("SNIFFER_TIMEOUT_MS")) && atoi(e) >= 10 && atoi(e) <= 60000)
        timeout_ms = atoi(e);

if (is_offline) {
        if (env_iface && env_iface[0])
            fprintf(stderr, "[*] SNIFFER_READ set; ignoring SNIFFER_IFACE='%s'.\n", env_iface);
        if (write_path && write_path[0])
            fprintf(stderr, "[*] SNIFFER_READ set; ignoring SNIFFER_WRITE (use live capture to record).\n");
        adhandle = pcap_open_offline(read_path, errbuf);
        if (!adhandle) {
            fprintf(stderr, "Unable to open pcap file '%s': %s\n", read_path, errbuf);
            return;
        }
        snprintf(devname, sizeof(devname), "%s", read_path);
    } else {
    pcap_if_t *alldevs = NULL, *d;
    int i = 0;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return;
    }

    printf("\n=== Available Devices ===\n");
    for (d = alldevs; d; d = d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description) printf(" - %s", d->description);
        print_mac(d->name);
        printf("\n");
    }

    if (i == 0) {
        printf("No interfaces found.\n");
        pcap_freealldevs(alldevs);
        return;
    }

    int dev_num = -1;
    if (env_iface) {
        // numeric or substring match
        char *end = NULL;
        long v = strtol(env_iface, &end, 10);
        if (end != env_iface && *end == '\0') {
            dev_num = pick_device(alldevs, i, (int)v);
        } else {
            int idx = 1;
            for (d = alldevs; d; d = d->next, idx++) {
                if (strstr(d->name, env_iface) ||
                    (d->description && strstr(d->description, env_iface))) {
                    dev_num = idx;
                    break;
                }
            }
        }
        if (dev_num < 0) {
            fprintf(stderr, "SNIFFER_IFACE='%s' did not match any device.\n", env_iface);
            pcap_freealldevs(alldevs);
            return;
        }
        printf("Using device %d via SNIFFER_IFACE.\n", dev_num);
    } else {
#ifdef _WIN32
        if (!GetConsoleWindow()) {
            fprintf(stderr, "No SNIFFER_IFACE set and no console for prompt. Set SNIFFER_IFACE.\n");
            pcap_freealldevs(alldevs);
            return;
        }
#endif
        printf("\nEnter device number to capture: ");
        fflush(stdout);
        if (scanf("%d", &dev_num) != 1) {
            fprintf(stderr, "Invalid input.\n");
            pcap_freealldevs(alldevs);
            return;
        }
    }

    if (dev_num < 1 || dev_num > i) {
        printf("Invalid device %d (valid 1..%d).\n", dev_num, i);
        pcap_freealldevs(alldevs);
        return;
    }

    d = alldevs;
    for (i = 1; i < dev_num && d; d = d->next, i++) {}
    if (!d) {
        printf("Invalid device.\n");
        pcap_freealldevs(alldevs);
        return;
    }

    snprintf(devname, sizeof(devname), "%s", d->name);

    adhandle = pcap_open_live(devname, snaplen, promisc, timeout_ms, errbuf);
    if (!adhandle) {
        fprintf(stderr, "Unable to open adapter: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        return;
    }
    pcap_freealldevs(alldevs);
    } // end live-device branch

    g_offline = is_offline;
    g_handle = adhandle;
    g_dlt = pcap_datalink(adhandle);

    // Optional BPF filter
    if (env_filter && env_filter[0]) {
        struct bpf_program fp;
        if (pcap_compile(adhandle, &fp, env_filter, 1, PCAP_NETMASK_UNKNOWN) == -1) {
            fprintf(stderr, "Bad filter '%s': %s\n", env_filter, pcap_geterr(adhandle));
        } else if (pcap_setfilter(adhandle, &fp) == -1) {
            fprintf(stderr, "Could not set filter: %s\n", pcap_geterr(adhandle));
        } else {
            printf("BPF filter: %s\n", env_filter);
        }
        pcap_freecode(&fp);
    }

    printf("Listening on %s (DLT=%d%s)... Press Ctrl+C to stop.\n",
           devname, g_dlt,
           is_offline ? ", offline replay" : "");

    pcap_dumper_t *dumper = NULL;
    if (!is_offline && write_path && write_path[0]) {
        dumper = pcap_dump_open(adhandle, write_path);
        if (!dumper) {
            fprintf(stderr, "Could not open %s for writing: %s\n",
                    write_path, pcap_geterr(adhandle));
        } else {
            printf("Recording capture to %s\n", write_path);
        }
    }

#ifdef _WIN32
    SetConsoleCtrlHandler(console_handler, TRUE);
#else
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigterm_handler);
#endif

    // Initialize queue and start analysis thread
    queue_init(&queue);
#ifdef _WIN32
    HANDLE hThread = CreateThread(NULL, 0, analysis_thread, NULL, 0, NULL);
    if (!hThread) {
        fprintf(stderr, "Failed to create analysis thread\n");
        pcap_close(adhandle);
        g_handle = NULL;
        queue_destroy(&queue);
        return;
    }
#else
    pthread_t thr;
    if (pthread_create(&thr, NULL, analysis_thread, NULL) != 0) {
        fprintf(stderr, "Failed to create analysis thread\n");
        pcap_close(adhandle);
        g_handle = NULL;
        queue_destroy(&queue);
        return;
    }
#endif

    // Start capture loop (main thread); breaks on Ctrl+C / error / EOF (offline rc 0/2 ok)
    int rc = pcap_loop(adhandle, 0, packet_handler, (u_char *)dumper);
    if (rc == -1) fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(adhandle));

    request_stop();
#ifdef _WIN32
    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
#else
    pthread_join(thr, NULL);
#endif
    printf("Queue drained. Dropped (queue full): %d\n", queue.dropped);
    if (!is_offline) {
    struct pcap_stat ps;
    if (pcap_stats(adhandle, &ps) == 0) {
        printf("Kernel stats: received=%u dropped=%u ifdropped=%u\n",
               ps.ps_recv, ps.ps_drop, ps.ps_ifdrop);
    }
    }
    queue_destroy(&queue);
    if (dumper) pcap_dump_close(dumper);
    pcap_close(adhandle);
    g_handle = NULL;
}
