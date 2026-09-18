// logger.c - Logging utility implementation (thread-safe, sanitized)
#include "logger.h"
#include <string.h>

// Default log level: INFO (reduce per-packet logging)
// Change to LOG_DEBUG for verbose per-packet output
volatile int current_log_level_int = LOG_INFO;

#ifdef _WIN32
CRITICAL_SECTION log_cs;
static int log_ready = 0;
#else
pthread_mutex_t log_cs = PTHREAD_MUTEX_INITIALIZER;
#endif

void log_init(void) {
#ifdef _WIN32
    if (!log_ready) {
        InitializeCriticalSection(&log_cs);
        log_ready = 1;
    }
#else
    // Statically initialized; nothing to do (kept for API symmetry)
    (void)0;
#endif
}

void sanitize_printable(char *s, unsigned long size) {
    if (!s || size == 0) return;
    for (unsigned long i = 0; i < size && s[i] != '\0'; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 32 || c > 126) s[i] = '.';
    }
}

void log_emit_stdout(const char *msg) {
#ifdef _WIN32
    if (log_ready) EnterCriticalSection(&log_cs);
    fputs(msg, stdout);
    fflush(stdout);
    if (log_ready) LeaveCriticalSection(&log_cs);
#else
    pthread_mutex_lock(&log_cs);
    fputs(msg, stdout);
    fflush(stdout);
    pthread_mutex_unlock(&log_cs);
#endif
}

void log_emit_stderr(const char *msg) {
#ifdef _WIN32
    if (log_ready) EnterCriticalSection(&log_cs);
    fputs(msg, stderr);
    if (log_ready) LeaveCriticalSection(&log_cs);
#else
    pthread_mutex_lock(&log_cs);
    fputs(msg, stderr);
    pthread_mutex_unlock(&log_cs);
#endif
}
