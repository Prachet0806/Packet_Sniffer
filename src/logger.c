// logger.c - Logging utility implementation
#include "logger.h"

// Default log level: INFO (reduce per-packet logging)
// Change to LOG_DEBUG for verbose per-packet output
LogLevel current_log_level = LOG_INFO;
