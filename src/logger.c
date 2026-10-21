#include "logger.h"
#include "util.h"
#include <string.h>
#include <stdint.h>
#include <signal.h>
#ifdef _WIN32
CRITICAL_SECTION log_cs;
#else
pthread_mutex_t log_cs;
#include <fcntl.h>
#include <unistd.h>
#endif
volatile int current_log_level_int = LOG_INFO;
#define LOG_QUEUE 256
static struct {
    int channel;
    char text[1024];
} messages[LOG_QUEUE];
static int ready, head, count;
static uint64_t dropped;
static atomic_flag_t stopping, discard;
static thread_t writer;
static void emit(int channel, const char *text) {
    if (!ready)
        return;
    mutex_lock(&log_cs);
    if (count == LOG_QUEUE) {
        dropped++;
        mutex_unlock(&log_cs);
        return;
    }
    int i = (head + count) % LOG_QUEUE;
    messages[i].channel = channel;
    snprintf(messages[i].text, sizeof(messages[i].text), "%s", text);
    count++;
    mutex_unlock(&log_cs);
}
#ifdef _WIN32
static DWORD WINAPI output_worker(LPVOID ignored) {
#else
static void *output_worker(void *ignored) {
#endif
    (void)ignored;
    for (;;) {
        if (flag_get(&discard))
            break;
        char text[1024];
        int channel = 0;
        mutex_lock(&log_cs);
        int empty = count == 0;
        if (!empty) {
            strcpy(text, messages[head].text);
            channel = messages[head].channel;
            head = (head + 1) % LOG_QUEUE;
            count--;
        }
        mutex_unlock(&log_cs);
        if (empty) {
            if (flag_get(&stopping))
                break;
            sleep_ms(5);
            continue;
        }
#ifdef _WIN32
        DWORD bytes;
        HANDLE out = GetStdHandle(channel ? STD_ERROR_HANDLE : STD_OUTPUT_HANDLE);
        if (!WriteFile(out, text, (DWORD)strlen(text), &bytes, NULL)) {
            mutex_lock(&log_cs);
            dropped++;
            mutex_unlock(&log_cs);
        }
#else
        size_t p = 0, n = strlen(text);
        int fd = channel ? STDERR_FILENO : STDOUT_FILENO;
        while (p < n) {
            ssize_t w = write(fd, text + p, n - p);
            if (w <= 0) {
                mutex_lock(&log_cs);
                dropped++;
                mutex_unlock(&log_cs);
                break;
            }
            p += (size_t)w;
        }
#endif
    }
    return 0;
}
void log_init(void) {
    if (ready)
        return;
    mutex_init(&log_cs);
    head = count = 0;
    dropped = 0;
    flag_set(&stopping, 0);
    flag_set(&discard, 0);
#ifndef _WIN32
    int fd = STDOUT_FILENO;
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    fd = STDERR_FILENO;
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
#endif
#ifdef _WIN32
    writer = CreateThread(NULL, 0, output_worker, NULL, 0, NULL);
    if (!writer)
        return;
#else
    if (pthread_create(&writer, NULL, output_worker, NULL))
        return;
#endif
    ready = 1;
}
void log_cleanup(void) {
    if (!ready)
        return;
    flag_set(&stopping, 1);
#ifdef _WIN32
    if (WaitForSingleObject(writer, 2000) == WAIT_TIMEOUT) {
        flag_set(&discard, 1);
        CancelSynchronousIo(writer);
    }
    WaitForSingleObject(writer, INFINITE);
    CloseHandle(writer);
#else
    pthread_join(writer, NULL);
#endif
    ready = 0;
    mutex_destroy(&log_cs);
}
uint64_t log_dropped(void) {
    if (!ready)
        return dropped;
    mutex_lock(&log_cs);
    uint64_t n = dropped;
    mutex_unlock(&log_cs);
    return n;
}
void sanitize_printable(char *s, unsigned long size) {
    if (!s)
        return;
    for (unsigned long i = 0; i < size && s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 32 || c > 126)
            s[i] = '.';
    }
}
void log_emit_stdout(const char *s) { emit(0, s); }
void log_emit_stderr(const char *s) { emit(1, s); }
