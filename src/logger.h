// logger.h - Logging utility with verbosity levels
#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>

// Log levels
typedef enum {
    LOG_ERROR = 0,   // Errors only
    LOG_WARN = 1,    // Warnings and errors
    LOG_INFO = 2,    // Info, warnings, and errors
    LOG_DEBUG = 3    // Everything including per-packet details
} LogLevel;

// Global log level (can be set via command line or config)
extern LogLevel current_log_level;

// Logging macros
#define LOG_ERROR_MSG(...) \
    do { if (LOG_ERROR <= current_log_level) fprintf(stderr, "[ERROR] " __VA_ARGS__); } while(0)

#define LOG_WARN_MSG(...) \
    do { if (LOG_WARN <= current_log_level) printf("[WARN] " __VA_ARGS__); } while(0)

#define LOG_INFO_MSG(...) \
    do { if (LOG_INFO <= current_log_level) printf("[INFO] " __VA_ARGS__); } while(0)

#define LOG_DEBUG_MSG(...) \
    do { if (LOG_DEBUG <= current_log_level) printf("[DEBUG] " __VA_ARGS__); } while(0)

// Simpler versions without level prefix (for backward compatibility)
#define LOG_ERROR_SIMPLE(...) \
    do { if (LOG_ERROR <= current_log_level) fprintf(stderr, __VA_ARGS__); } while(0)

#define LOG_WARN_SIMPLE(...) \
    do { if (LOG_WARN <= current_log_level) printf(__VA_ARGS__); } while(0)

#define LOG_INFO_SIMPLE(...) \
    do { if (LOG_INFO <= current_log_level) printf(__VA_ARGS__); } while(0)

#define LOG_DEBUG_SIMPLE(...) \
    do { if (LOG_DEBUG <= current_log_level) printf(__VA_ARGS__); } while(0)

#endif // LOGGER_H
