#include "sniffer.h"
#include "analyzer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <pcap.h>
#pragma comment(lib, "iphlpapi.lib")

// Configuration constants
#define MAX_QUEUE_SIZE 10000          // Maximum packets in queue
#define MAX_ADAPTERS 64               // Maximum network adapters

// ---------------------------
// Global Stop Flag and Statistics
// ---------------------------
volatile BOOL stop_sniffer = FALSE;

// Capture statistics (thread-safe atomic counters)
static volatile LONG64 packets_received = 0;
static volatile LONG64 packets_dropped_queue_full = 0;
static volatile LONG64 packets_dropped_alloc_fail = 0;
static volatile LONG64 queue_high_water_mark = 0;

// ---------------------------
// Thread-Safe Queue
// ---------------------------
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

// Initialize queue
void queue_init(PacketQueue *q) {
    q->head = q->tail = NULL;
    q->count = 0;
    InitializeCriticalSection(&q->cs);
    InitializeConditionVariable(&q->cv);
}

// Push packet to queue with size limit and error tracking
void queue_push(PacketQueue *q, const struct pcap_pkthdr *header, const u_char *data) {
    InterlockedIncrement64(&packets_received);
    
    // Check queue size limit first (before allocating memory)
    EnterCriticalSection(&q->cs);
    if (q->count >= MAX_QUEUE_SIZE) {
        LeaveCriticalSection(&q->cs);
        InterlockedIncrement64(&packets_dropped_queue_full);
        
        // Log periodically (every 1000 drops)
        LONG64 drops = packets_dropped_queue_full;
        if (drops % 1000 == 1) {
            fprintf(stderr, "[!] Queue full: dropped %lld packets (queue size: %d)\n", 
                    drops, MAX_QUEUE_SIZE);
        }
        return;
    }
    LeaveCriticalSection(&q->cs);
    
    // Allocate memory for node
    PacketNode *node = (PacketNode *)malloc(sizeof(PacketNode));
    if (!node) {
        InterlockedIncrement64(&packets_dropped_alloc_fail);
        if (packets_dropped_alloc_fail % 1000 == 1) {
            fprintf(stderr, "[!] Memory allocation failed: dropped %lld packets\n", 
                    packets_dropped_alloc_fail);
        }
        return;
    }
    
    node->header = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
    if (!node->header) {
        free(node);
        InterlockedIncrement64(&packets_dropped_alloc_fail);
        return;
    }
    
    node->data = (u_char *)malloc(header->caplen);
    if (!node->data) {
        free(node->header);
        free(node);
        InterlockedIncrement64(&packets_dropped_alloc_fail);
        return;
    }

    memcpy(node->header, header, sizeof(struct pcap_pkthdr));
    memcpy(node->data, data, header->caplen);
    node->next = NULL;

    EnterCriticalSection(&q->cs);
    if (q->tail) q->tail->next = node;
    else q->head = node;
    q->tail = node;
    q->count++;
    
    // Track high water mark
    if (q->count > queue_high_water_mark) {
        InterlockedExchange64(&queue_high_water_mark, q->count);
    }
    
    LeaveCriticalSection(&q->cs);
    WakeConditionVariable(&q->cv);
}

// Pop packet from queue
PacketNode* queue_pop(PacketQueue *q) {
    EnterCriticalSection(&q->cs);
    while (!q->head && !stop_sniffer) {
        SleepConditionVariableCS(&q->cv, &q->cs, INFINITE);
    }

    PacketNode *node = q->head;
    if (node) {
        q->head = node->next;
        if (!q->head) q->tail = NULL;
        q->count--;
    }
    LeaveCriticalSection(&q->cs);
    return node;
}

// Get queue count (thread-safe, for checking if queue is empty)
int queue_get_count(PacketQueue *q) {
    EnterCriticalSection(&q->cs);
    int count = q->count;
    LeaveCriticalSection(&q->cs);
    return count;
}

// Cleanup queue (must be called after stop_sniffer is set and analysis thread has finished)
void queue_cleanup(PacketQueue *q) {
    EnterCriticalSection(&q->cs);
    
    // Drain remaining packets in queue
    PacketNode *node = q->head;
    while (node) {
        PacketNode *next = node->next;
        free(node->header);
        free(node->data);
        free(node);
        node = next;
    }
    
    q->head = q->tail = NULL;
    q->count = 0;
    
    LeaveCriticalSection(&q->cs);
    DeleteCriticalSection(&q->cs);
}

// ---------------------------
// MAC Address Helper
// ---------------------------
static void print_mac(const char *guid) {
    IP_ADAPTER_INFO AdapterInfo[MAX_ADAPTERS];
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

// ---------------------------
// Ctrl+C Handler
// ---------------------------
BOOL WINAPI console_handler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_CLOSE_EVENT) {
        printf("\n[Sniffer] Ctrl+C detected. Stopping...\n");
        stop_sniffer = TRUE;
        WakeConditionVariable(&queue.cv); // wake analysis thread
        return TRUE;
    }
    return FALSE;
}

// ---------------------------
// Packet Handler (Capture Thread)
// ---------------------------
static void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    if (!stop_sniffer) {
        queue_push(&queue, header, pkt_data);
    }
}

// ---------------------------
// Analysis Thread
// ---------------------------
DWORD WINAPI analysis_thread(LPVOID param) {
    (void)param;  // Unused parameter
    while (!stop_sniffer || queue_get_count(&queue) > 0) {
        PacketNode *node = queue_pop(&queue);
        if (!node) {
            // If stop_sniffer is set and queue is empty, we're done
            if (stop_sniffer && queue_get_count(&queue) == 0) break;
            continue;
        }
        analyze_packet(node->header, node->data);
        free(node->header);
        free(node->data);
        free(node);
    }
    printf("[Sniffer] Analysis thread exiting\n");
    return 0;
}

// ---------------------------
// Start Sniffer
// ---------------------------
void start_sniffer() {
    SetConsoleCtrlHandler(console_handler, TRUE);

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
        pcap_freealldevs(alldevs);
        return;
    }

    int dev_num;
    char input[32];
    
    printf("\nEnter device number to capture: ");
    fflush(stdout);
    
    if (fgets(input, sizeof(input), stdin) == NULL) {
        printf("Failed to read input.\n");
        pcap_freealldevs(alldevs);
        return;
    }
    
    if (sscanf(input, "%d", &dev_num) != 1 || dev_num <= 0 || dev_num > i) {
        printf("Invalid device number. Please enter a number between 1 and %d.\n", i);
        pcap_freealldevs(alldevs);
        return;
    }

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

    printf("[Sniffer] Listening on %s...\n", d->name);

    // Initialize queue and start analysis thread
    queue_init(&queue);
    HANDLE hThread = CreateThread(NULL, 0, analysis_thread, NULL, 0, NULL);
    if (!hThread) {
        fprintf(stderr, "Failed to create analysis thread\n");
        pcap_freealldevs(alldevs);
        return;
    }

    // Capture loop with graceful exit
    while (!stop_sniffer) {
        pcap_dispatch(adhandle, 1, packet_handler, NULL);
    }

    // Cleanup
    printf("[Sniffer] Exiting...\n");
    pcap_breakloop(adhandle);
    pcap_close(adhandle);
    
    // Wait for analysis thread to finish processing remaining packets
    int queue_size = queue_get_count(&queue);
    DWORD timeout_ms = 10000 + (queue_size * 10);  // 10ms per packet + 10s base
    if (timeout_ms > 300000) timeout_ms = 300000;  // Cap at 5 minutes
    
    printf("[Sniffer] Waiting for analysis thread (%d packets in queue, timeout: %u ms)...\n", 
           queue_size, timeout_ms);
    
    DWORD wait_result = WaitForSingleObject(hThread, timeout_ms);
    if (wait_result == WAIT_TIMEOUT) {
        fprintf(stderr, "[!] Analysis thread did not finish in %u ms\n", timeout_ms);
        fprintf(stderr, "[!] Force terminating - may lose data!\n");
        TerminateThread(hThread, 1);
    }
    
    // Print capture statistics
    printf("\n=== Capture Statistics ===\n");
    printf("Packets received:         %lld\n", packets_received);
    printf("Packets queued:           %lld\n", 
           packets_received - packets_dropped_queue_full - packets_dropped_alloc_fail);
    printf("Dropped (queue full):     %lld\n", packets_dropped_queue_full);
    printf("Dropped (alloc failed):   %lld\n", packets_dropped_alloc_fail);
    printf("Queue high water mark:    %lld\n", queue_high_water_mark);
    if (packets_received > 0) {
        double drop_rate = (double)(packets_dropped_queue_full + packets_dropped_alloc_fail) / 
                          packets_received * 100.0;
        printf("Drop rate:                %.2f%%\n", drop_rate);
    }
    
    // Now safe to cleanup queue (analysis thread is done)
    queue_cleanup(&queue);
    CloseHandle(hThread);
    pcap_freealldevs(alldevs);
}