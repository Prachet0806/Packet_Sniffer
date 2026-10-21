#ifndef UTIL_H
#define UTIL_H
#include "os_compat.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#define JSMN_HEADER
#include "vendor/jsmn.h"
typedef struct {
    const char *text;
    jsmntok_t tokens[256];
    int count;
} JsonObject;
int json_parse(JsonObject *j, const char *text);
int json_find(const JsonObject *j, const char *key);
int json_u64(const JsonObject *j, int token, uint64_t *out);
int json_string(const JsonObject *j, int token, char *out, size_t capacity);
int json_quote(char *out, size_t capacity, const char *value);
int parse_integer(const char *text, long min, long max, long *out);
int env_integer(const char *name, long def, long min, long max, long *out);
uint64_t monotonic_ms(void);
int atomic_replace(const char *path, const char *data, size_t length);
#ifdef _WIN32
typedef volatile LONG atomic_flag_t;
static inline int flag_get(atomic_flag_t *f) { return (int)InterlockedCompareExchange(f, 0, 0); }
static inline void flag_set(atomic_flag_t *f, int v) { InterlockedExchange(f, v); }
#else
#include <stdatomic.h>
typedef atomic_int atomic_flag_t;
static inline int flag_get(atomic_flag_t *f) { return atomic_load(f); }
static inline void flag_set(atomic_flag_t *f, int v) { atomic_store(f, v); }
#endif
#endif
