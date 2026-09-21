// os_compat.h - minimal cross-platform threading/sleep/strcasecmp abstraction
#ifndef OS_COMPAT_H
#define OS_COMPAT_H

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
typedef CRITICAL_SECTION mutex_t;
typedef CONDITION_VARIABLE cond_t;
typedef HANDLE thread_t;

static inline void mutex_init(mutex_t *m) { InitializeCriticalSection(m); }
static inline void mutex_lock(mutex_t *m) { EnterCriticalSection(m); }
static inline void mutex_unlock(mutex_t *m) { LeaveCriticalSection(m); }
static inline void mutex_destroy(mutex_t *m) { DeleteCriticalSection(m); }
static inline void cond_init(cond_t *c) { InitializeConditionVariable(c); }
static inline void sleep_ms(unsigned ms) { Sleep(ms); }
static inline int strncasecmp_compat(const char *s1, const char *s2, size_t n) { return _strnicmp(s1, s2, n); }
#else
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <strings.h>
#include <string.h>
typedef pthread_mutex_t mutex_t;
typedef pthread_cond_t cond_t;
typedef pthread_t thread_t;

static inline void mutex_init(mutex_t *m) { pthread_mutex_init(m, NULL); }
static inline void mutex_lock(mutex_t *m) { pthread_mutex_lock(m); }
static inline void mutex_unlock(mutex_t *m) { pthread_mutex_unlock(m); }
static inline void mutex_destroy(mutex_t *m) { pthread_mutex_destroy(m); }
static inline void cond_init(cond_t *c) { pthread_cond_init(c, NULL); }
static inline void sleep_ms(unsigned ms) {
    struct timespec ts = { .tv_sec = 0, .tv_nsec = (long)ms * 1000000L };
    nanosleep(&ts, NULL);
}
#define strncasecmp_compat strncasecmp
#endif

#endif // OS_COMPAT_H
