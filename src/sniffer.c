// Multi-threaded packet sniffer
#include "sniffer.h"
#include "analyzer.h"
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winsock2.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")

// Thread-safe queue
typedef struct PacketNode {
    struct pcap_pkthdr *header;
    u_char *data;
    struct PacketNode *next;
} PacketNode;

typedef struct {
    PacketNode *head;
    PacketNode *tail;
    CRITICAL_SECTION cs;
    CONDITION_VARIABLE cv;
    int count;
} PacketQueue;

static PacketQueue queue;

void queue_init(PacketQueue *q) {
    q->head = q->tail = NULL;
    q->count = 0;
    InitializeCriticalSection(&q->cs);
    InitializeConditionVariable(&q->cv);
}

void queue_push(PacketQueue *q, const struct pcap_pkthdr *header, const u_char *data) {
    PacketNode *node = (PacketNode *)malloc(sizeof(PacketNode));
    node->header = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
    memcpy(node->header, header, sizeof(struct pcap_pkthdr));
    node->data = (u_char *)malloc(header->len);
    memcpy(node->data, data, header->len);
    node->next = NULL;

    EnterCriticalSection(&q->cs);
    if (q->tail) q->tail->next = node;
    else q->head = node;
    q->tail = node;
    q->count++;
    printf("[Queue] Pushed packet, new size = %d\n", q->count);
    LeaveCriticalSection(&q->cs);
    WakeConditionVariable(&q->cv);
}

PacketNode* queue_pop(PacketQueue *q) {
    EnterCriticalSection(&q->cs);
    while (!q->head) {
        SleepConditionVariableCS(&q->cv, &q->cs, INFINITE);
    }
    PacketNode *node = q->head;
    q->head = node->next;
    if (!q->head) q->tail = NULL;
    q->count--;
    printf("[Queue] Popped packet, new size = %d\n", q->count);
    LeaveCriticalSection(&q->cs);
    return node;
}

// MAC helper
static void print_mac(const char *guid) {
    IP_ADAPTER_INFO AdapterInfo[16];
    DWORD buflen = sizeof(AdapterInfo);
    if (GetAdaptersInfo(AdapterInfo, &buflen) != ERROR_SUCCESS) {
        printf(" (MAC: Unknown)");
        return;
    }
    PIP_ADAPTER_INFO pAdapter = AdapterInfo;
    while (pAdapter) {
        if (strstr(guid, pAdapter->AdapterName)) {
            printf(" (MAC: %02X:%02X:%02X:%02X:%02X:%02X)",
                   pAdapter->Address[0], pAdapter->Address[1],
                   pAdapter->Address[2], pAdapter->Address[3],
                   pAdapter->Address[4], pAdapter->Address[5]);
            return;
        }
        pAdapter = pAdapter->Next;
    }
    printf(" (MAC: Unknown)");
}

// Packet capture handler
static void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    printf("[Capture Thread] Captured packet length = %d\n", header->len);
    queue_push(&queue, header, pkt_data);
}

// Analysis thread
DWORD WINAPI analysis_thread(LPVOID param) {
    while (1) {
        PacketNode *node = queue_pop(&queue);
        printf("[Analysis Thread] Processing packet length = %d on thread %lu\n", node->header->len, GetCurrentThreadId());
        analyze_packet(node->header, node->data);

        free(node->header);
        free(node->data);
        free(node);
    }
    return 0;
}

// Sniffer
void start_sniffer() {
    pcap_if_t *alldevs, *d;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
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
        return;
    }

    int dev_num;
    printf("\nEnter device number to capture: ");
    scanf("%d", &dev_num);

    d = alldevs;
    for (i = 1; i < dev_num && d; d = d->next, i++);
    if (!d) {
        printf("Invalid device.\n");
        pcap_freealldevs(alldevs);
        return;
    }

    adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf);
    if (!adhandle) {
        fprintf(stderr, "Unable to open adapter: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        return;
    }

    printf("Listening on %s...\n", d->name);

    // Initialize queue and start analysis thread
    queue_init(&queue);
    HANDLE hThread = CreateThread(NULL, 0, analysis_thread, NULL, 0, NULL);
    if (!hThread) {
        fprintf(stderr, "Failed to create analysis thread\n");
        pcap_freealldevs(alldevs);
        return;
    }

    // Start capture loop (main thread)
    pcap_loop(adhandle, 0, packet_handler, NULL);

    pcap_freealldevs(alldevs);
}
