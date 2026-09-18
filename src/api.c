// api.c - minimal HTTP API (raw sockets, no external deps)
#include "api.h"
#include "stats.h"
#include "security.h"
#include "sniffer.h"
#include "logger.h"
#include "os_compat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef SOCKET sock_t;
#define SOCK_INVALID INVALID_SOCKET
#define SOCK_CLOSE closesocket
#else
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <fcntl.h>
#include <errno.h>
typedef int sock_t;
#define SOCK_INVALID -1
#define SOCK_CLOSE close
#endif

static volatile int api_run = 0;
static thread_t api_thr;
static int api_started = 0;
static time_t api_t0 = 0;
static int api_port = 0;
static char api_bind[64] = "127.0.0.1";
static char api_token[256] = {0};
#ifdef _WIN32
static int wsa_initialized = 0;
#endif

// simple rate limit: >60 reqs / 10s -> 429
static time_t rl_win = 0;
static int rl_n = 0;

static int const_time_eq(const char *a, const char *b) {
    size_t la = a ? strlen(a) : 0, lb = b ? strlen(b) : 0;
    size_t n = la > lb ? la : lb;
    unsigned diff = (unsigned)(la ^ lb);
    for (size_t i = 0; i < n; i++) {
        char ca = i < la ? a[i] : 0, cb = i < lb ? b[i] : 0;
        diff |= (unsigned)(ca ^ cb);
    }
    return diff == 0;
}

static int stats_to_json(char *out, int n) {
    ProtocolStats snap;
#ifdef _WIN32
    EnterCriticalSection(&stats_cs); snap = stats; LeaveCriticalSection(&stats_cs);
#else
    pthread_mutex_lock(&stats_cs); snap = stats; pthread_mutex_unlock(&stats_cs);
#endif
    return stats_format_json(out, n, &snap, 0);
}

static void send_resp(sock_t c, int code, const char *ctype, const char *body) {
    const char *st = code == 200 ? "OK" : code == 401 ? "Unauthorized" :
        code == 404 ? "Not Found" : code == 429 ? "Too Many Requests" :
        code == 400 ? "Bad Request" : code == 403 ? "Forbidden" : "Error";
    char hdr[512];
    int bl = body ? (int)strlen(body) : 0;
    int hl = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
        code, st, ctype ? ctype : "application/json", bl);
    send(c, hdr, hl, 0);
    if (bl) send(c, body, bl, 0);
}

static void handle_client(sock_t c) {
    char req[8192] = {0};
    int got = recv(c, req, (int)sizeof(req) - 1, 0);
    if (got <= 0) return;
    req[got] = '\0';

    char method[16] = {0}, path[256] = {0};
    sscanf(req, "%15s %255s", method, path);

    // rate limit
    time_t now = time(NULL);
    if (now - rl_win > 10) { rl_win = now; rl_n = 0; }
    if (++rl_n > 60) { send_resp(c, 429, "application/json", "{\"error\":\"rate-limited\"}"); return; }

    // auth (token required when API enabled)
    if (api_token[0]) {
        const char *ah = strstr(req, "Authorization:");
        char tok[300] = {0};
        if (ah) sscanf(ah, "Authorization: Bearer %299s", tok);
        // trim CRLF
        tok[strcspn(tok, "\r\n ")] = '\0';
        if (!const_time_eq(tok, api_token)) {
            send_resp(c, 401, "application/json", "{\"error\":\"unauthorized\"}");
            return;
        }
    }

    if (strcmp(method, "GET") == 0 && strcmp(path, "/health") == 0) {
        char b[128];
        snprintf(b, sizeof(b), "{\"ok\":true,\"uptime\":%lld}", (long long)(now - api_t0));
        send_resp(c, 200, "application/json", b);
    } else if (strcmp(method, "GET") == 0 && strcmp(path, "/stats") == 0) {
        static char b[2048];
        stats_to_json(b, sizeof(b));
        send_resp(c, 200, "application/json", b);
    } else if (strcmp(method, "GET") == 0 && strcmp(path, "/alerts") == 0) {
        static char b[16384];
        security_get_alerts(b, sizeof(b));
        send_resp(c, 200, "application/json", b);
    } else if (strcmp(method, "POST") == 0 && strcmp(path, "/filter") == 0) {
        if (sniffer_is_offline()) { send_resp(c, 403, "application/json", "{\"error\":\"filter not allowed in --read mode\"}"); return; }
        // body = raw BPF or {"bpf":"..."}
        const char *body = strstr(req, "\r\n\r\n");
        body = body ? body + 4 : "";
        char bpf[512] = {0};
        const char *k = strstr(body, "\"bpf\"");
        if (k) { k = strchr(k, ':'); if (k) { k++; while (*k==' '||*k=='\"') k++; int i=0; while (*k && *k!='\"' && *k!='\r' && *k!='\n' && i+1<(int)sizeof(bpf)) bpf[i++]=*k++; } }
        else { snprintf(bpf, sizeof(bpf), "%s", body); bpf[strcspn(bpf, "\r\n")] = '\0'; }
        if (!bpf[0]) { send_resp(c, 400, "application/json", "{\"error\":\"missing bpf\"}"); return; }
        
        // Basic BPF filter validation: length and forbidden patterns
        if (strlen(bpf) > 400) { send_resp(c, 400, "application/json", "{\"error\":\"filter too long\"}"); return; }
        // Reject filters with shell metacharacters (defense in depth)
        for (const char *p = bpf; *p; p++) {
            if (*p == ';' || *p == '|' || *p == '&' || *p == '$' || *p == '`' || *p == '(' || *p == ')') {
                send_resp(c, 400, "application/json", "{\"error\":\"invalid characters in filter\"}"); return;
            }
        }
        
        int rc = sniffer_apply_filter(bpf);
        if (rc == 0) send_resp(c, 200, "application/json", "{\"ok\":true}");
        else send_resp(c, 400, "application/json", "{\"error\":\"bad filter\"}");
    } else {
        send_resp(c, 404, "application/json", "{\"error\":\"not found\"}");
    }
}

#ifdef _WIN32
static DWORD WINAPI api_loop(LPVOID p) {
#else
static void *api_loop(void *p) {
#endif
    (void)p;
    sock_t ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls == SOCK_INVALID) { LOG_ERROR_MSG("api: socket failed\n"); return 0; }
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof(one));
    struct sockaddr_in a; memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET; a.sin_port = htons((unsigned short)api_port);
    a.sin_addr.s_addr = inet_addr(api_bind);
    if (bind(ls, (struct sockaddr*)&a, sizeof(a)) != 0) {
        LOG_ERROR_MSG("api: bind %s:%d failed\n", api_bind, api_port);
        SOCK_CLOSE(ls); return 0;
    }
    if (listen(ls, 8) != 0) { SOCK_CLOSE(ls); return 0; }
    LOG_INFO_SIMPLE("API listening on %s:%d\n", api_bind, api_port);
    while (api_run) {
        fd_set rf; FD_ZERO(&rf); FD_SET(ls, &rf);
        struct timeval tv; tv.tv_sec = 0; tv.tv_usec = 300000;
        int r = select((int)(ls + 1), &rf, NULL, NULL, &tv);
        if (!api_run) break;
        if (r > 0 && FD_ISSET(ls, &rf)) {
            sock_t c = accept(ls, NULL, NULL);
            if (c != SOCK_INVALID) { handle_client(c); SOCK_CLOSE(c); }
        }
    }
    SOCK_CLOSE(ls);
    return 0;
}

int api_start(void) {
    const char *pe = getenv("SNIFFER_API_PORT");
    if (!pe || !pe[0] || atoi(pe) == 0) return 0; // opt-in
    api_port = atoi(pe);
    const char *be = getenv("SNIFFER_API_BIND");
    if (be && be[0]) snprintf(api_bind, sizeof(api_bind), "%s", be);
    const char *te = getenv("SNIFFER_API_TOKEN");
    if (te && te[0]) snprintf(api_token, sizeof(api_token), "%s", te);
    if (!api_token[0]) {
        LOG_ERROR_MSG("api: SNIFFER_API_TOKEN required when API port enabled\n");
        return -1;
    }
    if (api_port <= 0 || api_port > 65535) return -1;
#ifdef _WIN32
    if (!wsa_initialized) {
        WSADATA wd;
        if (WSAStartup(MAKEWORD(2,2), &wd) != 0) {
            LOG_ERROR_MSG("api: WSAStartup failed\n");
            return -1;
        }
        wsa_initialized = 1;
    }
#endif
    api_t0 = time(NULL);
    api_run = 1;
#ifdef _WIN32
    HANDLE h = CreateThread(NULL, 0, api_loop, NULL, 0, NULL);
    if (!h) { api_run = 0; return -1; }
    api_thr = h;
#else
    if (pthread_create(&api_thr, NULL, api_loop, NULL) != 0) { api_run = 0; return -1; }
#endif
    api_started = 1;
    return 0;
}

void api_stop(void) {
    if (!api_started) return;
    api_run = 0;
#ifdef _WIN32
    WaitForSingleObject(api_thr, 3000);
    CloseHandle(api_thr);
    if (wsa_initialized) {
        WSACleanup();
        wsa_initialized = 0;
    }
#else
    pthread_join(api_thr, NULL);
#endif
    api_started = 0;
}

int api_is_running(void) { return api_started && api_run; }
