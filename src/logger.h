// logger.h - Logging utility with verbosity levels (thread-safe)
#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

// Log levels
typedef enum {
    LOG_ERROR = 0,   // Errors only
    LOG_WARN = 1,    // Warnings and errors
    LOG_INFO = 2,    // Info, warnings, and errors
    LOG_DEBUG = 3    // Everything including per-packet details
} LogLevel;

// Global log level (set at startup; read concurrently afterwards)
extern volatile int current_log_level_int;
#define current_log_level (current_log_level_int)

// Serialize all log output so capture + analysis threads don't interleave
#ifdef _WIN32
extern CRITICAL_SECTION log_cs;
#else
extern pthread_mutex_t log_cs;
#endif
void log_init(void);

// Replace non-printable bytes (incl. ESC) with '.' — packet data must never
// reach the terminal raw (ANSI-escape injection).
void sanitize_printable(char *s, unsigned long size);

// Internal locked emitters (use the macros below, not these directly)
void log_emit_stdout(const char *msg);
void log_emit_stderr(const char *msg);

// Logging macros (locked, level-checked)
#define LOG_ERROR_MSG(...) \
    do { if (LOG_ERROR <= current_log_level_int) { \
        char _lb[1024]; snprintf(_lb, sizeof(_lb), "[ERROR] " __VA_ARGS__); \
        log_emit_stderr(_lb); } } while(0)

#define LOG_WARN_MSG(...) \
    do { if (LOG_WARN <= current_log_level_int) { \
        char _lb[1024]; snprintf(_lb, sizeof(_lb), "[WARN] " __VA_ARGS__); \
        log_emit_stdout(_lb); } } while(0)

#define LOG_INFO_MSG(...) \
    do { if (LOG_INFO <= current_log_level_int) { \
        char _lb[1024]; snprintf(_lb, sizeof(_lb), "[INFO] " __VA_ARGS__); \
        log_emit_stdout(_lb); } } while(0)

#define LOG_DEBUG_MSG(...) \
    do { if (LOG_DEBUG <= current_log_level_int) { \
        char _lb[1024]; snprintf(_lb, sizeof(_lb), "[DEBUG] " __VA_ARGS__); \
        log_emit_stdout(_lb); } } while(0)

// Simpler versions without level prefix (for backward compatibility)
#define LOG_ERROR_SIMPLE(...) \
    do { if (LOG_ERROR <= current_log_level_int) { \
        char _lb[1024]; snprintf(_lb, sizeof(_lb), __VA_ARGS__); \
        log_emit_stderr(_lb); } } while(0)

#define LOG_WARN_SIMPLE(...) \
    do { if (LOG_WARN <= current_log_level_int) { \
        char _lb[1024]; snprintf(_lb, sizeof(_lb), __VA_ARGS__); \
        log_emit_stdout(_lb); } } while(0)

#define LOG_INFO_SIMPLE(...) \
    do { if (LOG_INFO <= current_log_level_int) { \
        char _lb[1024]; snprintf(_lb, sizeof(_lb), __VA_ARGS__); \
        log_emit_stdout(_lb); } } while(0)

#define LOG_DEBUG_SIMPLE(...) \
    do { if (LOG_DEBUG <= current_log_level_int) { \
        char _lb[1024]; snprintf(_lb, sizeof(_lb), __VA_ARGS__); \
        log_emit_stdout(_lb); } } while(0)

#endif // LOGGER_H
