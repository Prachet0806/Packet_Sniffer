#include "api.h"
#include "stats.h"
#include "security.h"
#include "sniffer.h"
#include "logger.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <ws2tcpip.h>
typedef SOCKET sock_t;
#define INVALID_FD INVALID_SOCKET
#define CLOSE closesocket
#else
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
typedef int sock_t;
#define INVALID_FD -1
#define CLOSE close
#endif
#define CLIENTS 16
#define REQUEST 8192
#define RESPONSE 65536
static atomic_flag_t run;
static thread_t thread;
static sock_t listener = INVALID_FD;
static int started;
#ifdef _WIN32
static int wsa;
#endif
static char token[256], control_token[256];
static uint64_t startup;
typedef struct {
    sock_t fd;
    char req[REQUEST], response[RESPONSE];
    size_t used, size, sent;
    uint64_t deadline;
    uint32_t ip;
} Client;
static Client clients[CLIENTS];
typedef struct {
    uint32_t ip;
    int credential;
    uint64_t start, last;
    int count;
} Rate;
static Rate rates[64];
static int nonblock(sock_t fd) {
#ifdef _WIN32
    u_long yes = 1;
    return ioctlsocket(fd, FIONBIO, &yes);
#else
    return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
#endif
}
static int would_block(void) {
#ifdef _WIN32
    return WSAGetLastError() == WSAEWOULDBLOCK;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
#endif
}
static int secret_equal(const char *a, const char *b) {
    size_t x = strlen(a), y = strlen(b), n = x > y ? x : y;
    unsigned diff = (unsigned)(x ^ y);
    for (size_t i = 0; i < n; i++)
        diff |= (unsigned)((i < x ? a[i] : 0) ^ (i < y ? b[i] : 0));
    return diff == 0;
}
static void response(Client *c, int status, const char *body) {
    const char *reason = status == 200   ? "OK"
                         : status == 400 ? "Bad Request"
                         : status == 401 ? "Unauthorized"
                         : status == 403 ? "Forbidden"
                         : status == 404 ? "Not Found"
                         : status == 429 ? "Too Many Requests"
                         : status == 503 ? "Service Unavailable"
                                         : "Error";
    int n = snprintf(c->response, sizeof(c->response),
                     "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: "
                     "%zu\r\nConnection: close\r\n\r\n%s",
                     status, reason, strlen(body), body);
    if (n < 0 || (size_t)n >= sizeof(c->response)) {
        c->size = 0;
        c->deadline = 0;
        return;
    }
    c->size = (size_t)n;
    c->deadline = monotonic_ms() + 2000;
}
static int rate_limit(uint32_t ip, int credential) {
    uint64_t now = monotonic_ms();
    Rate *a = NULL, *slot = &rates[0];
    for (int i = 0; i < 64; i++) {
        if (rates[i].ip == ip && rates[i].credential == credential && rates[i].last)
            a = &rates[i];
        if (!rates[i].last || rates[i].last < slot->last)
            slot = &rates[i];
    }
    if (!a) {
        a = slot;
        memset(a, 0, sizeof(*a));
        a->ip = ip;
        a->credential = credential;
    }
    if (now - a->start >= 10000) {
        a->start = now;
        a->count = 0;
    }
    a->last = now;
    return ++a->count > 60;
}
static int parse_headers(Client *c, char *method, char *path, char *auth, size_t *body_length,
                         size_t *header_length) {
    char *end = strstr(c->req, "\r\n\r\n");
    if (!end)
        return c->used >= REQUEST - 1 ? -1 : 0;
    *header_length = (size_t)(end - c->req) + 4;
    *body_length = 0;
    auth[0] = 0;
    char version[16], extra;
    char *line = strstr(c->req, "\r\n");
    if (!line)
        return -1;
    char first[512];
    size_t n = (size_t)(line - c->req);
    if (n >= sizeof(first))
        return -1;
    memcpy(first, c->req, n);
    first[n] = 0;
    if (sscanf(first, "%15s %255s %15s %c", method, path, version, &extra) != 3 ||
        strcmp(version, "HTTP/1.1"))
        return -1;
    char *p = line + 2;
    int have_length = 0, have_auth = 0;
    while (p < end) {
        char *e = strstr(p, "\r\n");
        if (!e || e > end)
            return -1;
        char *colon = memchr(p, ':', (size_t)(e - p));
        if (!colon || colon == p)
            return -1;
        size_t key = (size_t)(colon - p);
        const char *v = colon + 1;
        while (v < e && (*v == ' ' || *v == '\t'))
            v++;
        const char *ve = e;
        while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t'))
            ve--;
        if (key == 14 && !strncasecmp_compat(p, "Content-Length", 14)) {
            char b[32];
            size_t len = (size_t)(ve - v);
            long length;
            if (have_length++ || len >= sizeof(b))
                return -1;
            memcpy(b, v, len);
            b[len] = 0;
            if (!b[0] || strspn(b, "0123456789") != strlen(b) || parse_integer(b, 0, 4096, &length))
                return -1;
            *body_length = (size_t)length;
        }
        if (key == 17 && !strncasecmp_compat(p, "Transfer-Encoding", 17))
            return -1;
        if (key == 13 && !strncasecmp_compat(p, "Authorization", 13)) {
            size_t len = (size_t)(ve - v);
            if (have_auth++ || len < 8 || len >= 300 || strncasecmp_compat(v, "Bearer ", 7))
                return -1;
            len -= 7;
            memcpy(auth, v + 7, len);
            auth[len] = 0;
        }
        for (char *q = p; q < e; q++)
            if ((unsigned char)*q < 32 && *q != '\t')
                return -1;
        p = e + 2;
    }
    if (*header_length + *body_length >= REQUEST)
        return -1;
    return c->used >= *header_length + *body_length ? 1 : 0;
}
static void process(Client *c) {
    char method[16], path[256], auth[300];
    size_t length, header;
    int parsed = parse_headers(c, method, path, auth, &length, &header);
    if (parsed == 0)
        return;
    if (parsed < 0) {
        response(c, 400, "{\"error\":\"invalid HTTP request\"}");
        return;
    }
    if (c->used != header + length) {
        response(c, 400, "{\"error\":\"unexpected trailing data\"}");
        return;
    }
    int reader = secret_equal(auth, token);
    int controller = control_token[0] && secret_equal(auth, control_token);
    if (rate_limit(c->ip, controller ? 2 : reader ? 1 : 0)) {
        response(c, 429, "{\"error\":\"rate limited\"}");
        return;
    }
    if (!reader && !controller) {
        response(c, 401, "{\"error\":\"unauthorized\"}");
        return;
    }
    if (!strcmp(method, "GET") && !strcmp(path, "/health")) {
        char capture[1024], persist[1024], b[4096];
        sniffer_health_json(capture, sizeof(capture));
        stats_health_json(persist, sizeof(persist));
        snprintf(b, sizeof(b),
                 "{\"alive\":true,\"uptime_ms\":%llu,\"persistence\":%s,\"capture\":%s}",
                 (unsigned long long)(monotonic_ms() - startup), persist, capture);
        response(c, 200, b);
    } else if (!strcmp(method, "GET") && !strcmp(path, "/stats")) {
        ProtocolStats s;
        stats_snapshot(&s);
        char b[8192];
        if (stats_format_json(b, sizeof(b), &s, 0) < 0)
            response(c, 503, "{\"error\":\"statistics unavailable\"}");
        else
            response(c, 200, b);
    } else if (!strcmp(method, "GET") && !strncmp(path, "/alerts", 7) &&
               (path[7] == 0 || path[7] == '?')) {
        unsigned offset = 0, limit = 32;
        if (path[7]) {
            char *q = path + 8;
            while (*q) {
                char *end = strchr(q, '&');
                if (end)
                    *end = 0;
                char *equals = strchr(q, '=');
                long value;
                if (!equals) {
                    response(c, 400, "{\"error\":\"invalid pagination\"}");
                    return;
                }
                *equals++ = 0;
                if (parse_integer(equals, 0, 128, &value)) {
                    response(c, 400, "{\"error\":\"invalid pagination\"}");
                    return;
                }
                if (!strcmp(q, "offset"))
                    offset = (unsigned)value;
                else if (!strcmp(q, "limit") && value > 0 && value <= 32)
                    limit = (unsigned)value;
                else {
                    response(c, 400, "{\"error\":\"invalid pagination\"}");
                    return;
                }
                if (!end)
                    break;
                q = end + 1;
            }
        }
        char b[60000];
        if (security_get_alert_page(b, sizeof(b), offset, limit) < 0)
            response(c, 503, "{\"error\":\"alert response exceeds limit\"}");
        else
            response(c, 200, b);
    } else if (!strcmp(method, "POST") && !strcmp(path, "/filter")) {
        if (control_token[0] && !controller) {
            response(c, 403, "{\"error\":\"control credential required\"}");
            return;
        }
        if (sniffer_is_offline()) {
            response(c, 403, "{\"error\":\"offline capture\"}");
            return;
        }
        JsonObject j;
        char bpf[512];
        if (!length || json_parse(&j, c->req + header) || j.count != 3 ||
            json_string(&j, json_find(&j, "bpf"), bpf, sizeof(bpf)) || !bpf[0]) {
            response(c, 400, "{\"error\":\"expected bpf JSON string\"}");
            return;
        }
        int rc = sniffer_apply_filter(bpf);
        response(c,
                 rc == 0    ? 200
                 : rc == -1 ? 400
                            : 503,
                 rc == 0 ? "{\"ok\":true}"
                         : "{\"error\":\"filter rejected or capture unavailable\"}");
    } else
        response(c, 404, "{\"error\":\"not found\"}");
}
static void close_client(Client *c) {
    if (c->fd != INVALID_FD)
        CLOSE(c->fd);
    c->fd = INVALID_FD;
}
#ifdef _WIN32
static DWORD WINAPI api_loop(LPVOID unused) {
#else
static void *api_loop(void *unused) {
#endif
    (void)unused;
    while (flag_get(&run)) {
        fd_set rd, wr;
        FD_ZERO(&rd);
        FD_ZERO(&wr);
        FD_SET(listener, &rd);
        sock_t max = listener;
        uint64_t now = monotonic_ms();
        for (int i = 0; i < CLIENTS; i++) {
            Client *c = &clients[i];
            if (c->fd == INVALID_FD)
                continue;
            if (now >= c->deadline) {
                close_client(c);
                continue;
            }
            if (c->size)
                FD_SET(c->fd, &wr);
            else
                FD_SET(c->fd, &rd);
            if (c->fd > max)
                max = c->fd;
        }
        struct timeval tv = {0, 20000};
        int n = select((int)max + 1, &rd, &wr, NULL, &tv);
        if (n < 0) {
            if (would_block())
                continue;
            break;
        }
        if (!flag_get(&run))
            break;
        if (FD_ISSET(listener, &rd)) {
            struct sockaddr_in addr;
#ifdef _WIN32
            int len = sizeof(addr);
#else
            socklen_t len = sizeof(addr);
#endif
            sock_t fd = accept(listener, (struct sockaddr *)&addr, &len);
            if (fd != INVALID_FD) {
                int i;
                for (i = 0; i < CLIENTS; i++)
                    if (clients[i].fd == INVALID_FD)
                        break;
                if (i == CLIENTS || nonblock(fd))
                    CLOSE(fd);
                else {
                    Client *c = &clients[i];
                    memset(c, 0, sizeof(*c));
                    c->fd = fd;
                    c->ip = addr.sin_addr.s_addr;
                    c->deadline = monotonic_ms() + 2000;
                }
            }
        }
        for (int i = 0; i < CLIENTS; i++) {
            Client *c = &clients[i];
            if (c->fd == INVALID_FD)
                continue;
            if (!c->size && FD_ISSET(c->fd, &rd)) {
                int got = recv(c->fd, c->req + c->used, (int)(REQUEST - 1 - c->used), 0);
                if (got <= 0) {
                    if (got == 0 || !would_block())
                        close_client(c);
                    continue;
                }
                c->used += (size_t)got;
                c->req[c->used] = 0;
                if (memchr(c->req, 0, c->used)) {
                    response(c, 400, "{\"error\":\"NUL in request\"}");
                } else
                    process(c);
            }
            if (c->size && FD_ISSET(c->fd, &wr)) {
#ifdef MSG_NOSIGNAL
                int flags = MSG_NOSIGNAL;
#else
                int flags = 0;
#endif
                int sent = send(c->fd, c->response + c->sent, (int)(c->size - c->sent), flags);
                if (sent > 0) {
                    c->sent += (size_t)sent;
                    if (c->sent == c->size)
                        close_client(c);
                } else if (!would_block())
                    close_client(c);
            }
        }
    }
    for (int i = 0; i < CLIENTS; i++)
        close_client(&clients[i]);
    flag_set(&run, 0);
    return 0;
}
int api_start(void) {
    long port;
    if (env_integer("SNIFFER_API_PORT", 0, 0, 65535, &port))
        return -1;
    if (!port)
        return 0;
    if (started)
        return -1;
    const char *t = getenv("SNIFFER_API_TOKEN"), *ct = getenv("SNIFFER_API_CONTROL_TOKEN"),
               *bind_addr = getenv("SNIFFER_API_BIND");
    if (!t || !*t || strlen(t) >= sizeof(token) || (ct && strlen(ct) >= sizeof(control_token)))
        return -1;
    strcpy(token, t);
    snprintf(control_token, sizeof(control_token), "%s", ct ? ct : "");
#ifdef _WIN32
    WSADATA wd;
    if (WSAStartup(MAKEWORD(2, 2), &wd))
        return -1;
    wsa = 1;
#endif
    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener == INVALID_FD)
        goto fail;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, bind_addr ? bind_addr : "127.0.0.1", &a.sin_addr) != 1)
        goto fail;
    if (bind(listener, (struct sockaddr *)&a, sizeof(a)) || listen(listener, CLIENTS) ||
        nonblock(listener))
        goto fail;
    for (int i = 0; i < CLIENTS; i++)
        clients[i].fd = INVALID_FD;
    memset(rates, 0, sizeof(rates));
    startup = monotonic_ms();
    flag_set(&run, 1);
#ifdef _WIN32
    thread = CreateThread(NULL, 0, api_loop, NULL, 0, NULL);
    if (!thread)
        goto fail;
#else
    if (pthread_create(&thread, NULL, api_loop, NULL))
        goto fail;
#endif
    started = 1;
    return 0;
fail:
    flag_set(&run, 0);
    if (listener != INVALID_FD) {
        CLOSE(listener);
        listener = INVALID_FD;
    }
#ifdef _WIN32
    if (wsa) {
        WSACleanup();
        wsa = 0;
    }
#endif
    return -1;
}
void api_stop(void) {
    if (!started)
        return;
    flag_set(&run, 0);
#ifdef _WIN32
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
#else
    pthread_join(thread, NULL);
#endif
    CLOSE(listener);
    listener = INVALID_FD;
    started = 0;
#ifdef _WIN32
    if (wsa) {
        WSACleanup();
        wsa = 0;
    }
#endif
}
int api_is_running(void) { return started && flag_get(&run); }
