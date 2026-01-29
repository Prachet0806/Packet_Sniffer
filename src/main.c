// main.c - Packet Sniffer + Protocol Analyzer
#include "sniffer.h"
#include "stats.h"
#include <ctype.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

// Configuration constants
#define MAX_LINE_LENGTH 2048
#define MAX_ENV_ENTRY 2048

// Default to local docker for dev; override via AWS_RDS_CONNINFO
static const char *DEFAULT_POSTGRES_CONNINFO =
    "host=localhost port=5432 dbname=snifferdb user=sniffer password=snifferpass sslmode=disable";

// Global exit flag for signal handler (async-signal-safe)
static volatile sig_atomic_t exit_requested = 0;

// Trim whitespace in-place (leading + trailing)
static void trim(char *s) {
    if (!s) return;
    char *start = s;
    while (*start && isspace((unsigned char)*start)) start++;
    if (start != s) memmove(s, start, strlen(start) + 1);
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) {
        s[len - 1] = '\0';
        len--;
    }
}

// Basic .env loader (KEY=VALUE per line, # for comments)
static void load_env_file(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return;

    char line[MAX_LINE_LENGTH];
    int loaded_count = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        // Strip newline
        size_t len = strlen(line);
        if (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[len - 1] = '\0';
            if (len > 1 && line[len - 2] == '\r') line[len - 2] = '\0';
        }

        // Skip comments/empty
        trim(line);
        if (line[0] == '\0' || line[0] == '#') continue;

        char *eq = strchr(line, '=');
        if (!eq) continue;

        *eq = '\0';
        char *key = line;
        char *val = eq + 1;
        trim(key);
        trim(val);
        if (key[0] == '\0') continue;

        // Build "KEY=VALUE" for _putenv with overflow protection
        char env_entry[MAX_ENV_ENTRY];
        int written = snprintf(env_entry, sizeof(env_entry), "%s=%s", key, val);
        
        if (written < 0 || written >= (int)sizeof(env_entry)) {
            fprintf(stderr, "[!] Warning: Environment variable truncated: %s\n", key);
            continue;
        }
        
        if (_putenv(env_entry) != 0) {
            fprintf(stderr, "[!] Warning: Failed to set environment variable: %s\n", key);
        } else {
            loaded_count++;
        }
    }

    fclose(fp);
    if (loaded_count > 0) {
        printf("[+] Loaded %d environment variables from %s\n", loaded_count, path);
    }
}

static const char* get_postgres_conninfo(void) {
    // Check for AWS RDS connection
    const char *env_conn = getenv("AWS_RDS_CONNINFO");
    if (env_conn && env_conn[0] != '\0') {
        printf("[+] Using Postgres conninfo from AWS_RDS_CONNINFO\n");
        return env_conn;
    }

    // Fall back to local Docker default
    printf("[!] AWS_RDS_CONNINFO not set, using local default (Docker)\n");
    return DEFAULT_POSTGRES_CONNINFO;
}

// Ctrl+C handler (async-signal-safe - only sets flag)
void handle_exit(int sig) {
    (void)sig; // Unused
    exit_requested = 1;  // Only async-signal-safe operations allowed here
}

int main() {
    printf("=== Packet Sniffer + Protocol Analyzer ===\n");

    // Load environment overrides from .env if present
    load_env_file(".env");

    // Initialize stats module with Postgres connection info
    const char *conninfo = get_postgres_conninfo();
    stats_init(conninfo);

    // Set Ctrl+C handler
    signal(SIGINT, handle_exit);

    // Start packet capture loop (blocking)
    start_sniffer();

    // Check if exit was requested via signal
    if (exit_requested) {
        printf("\n[!] Ctrl+C detected, shutting down gracefully...\n");
    }

    // Cleanup in main context (safe - not in signal handler)
    printf("[+] Cleaning up...\n");
    stats_cleanup();

    printf("[+] Exiting sniffer.\n");
    return 0;
}
