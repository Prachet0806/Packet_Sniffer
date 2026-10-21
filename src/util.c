#include "util.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <inttypes.h>
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#include <fcntl.h>
#endif
#undef JSMN_HEADER
#include "vendor/jsmn.h"

int parse_integer(const char *s, long min, long max, long *out) {
    char *end;
    long v;
    if (!s || !*s || !out || isspace((unsigned char)*s))
        return -1;
    errno = 0;
    v = strtol(s, &end, 10);
    if (errno || *end || v < min || v > max)
        return -1;
    *out = v;
    return 0;
}
int env_integer(const char *name, long def, long min, long max, long *out) {
    const char *s = getenv(name);
    if (!s) {
        *out = def;
        return 0;
    }
    if (parse_integer(s, min, max, out)) {
        fprintf(stderr, "Invalid numeric configuration: %s\n", name);
        return -1;
    }
    return 0;
}
uint64_t monotonic_ms(void) {
#ifdef _WIN32
    return GetTickCount64();
#else
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
#endif
}
static const char *skip_space(const char *p) {
    while (*p && isspace((unsigned char)*p))
        p++;
    return p;
}
int json_parse(JsonObject *j, const char *text) {
    jsmn_parser parser;
    const char *p;
    int i;
    if (!j || !text || strlen(text) > 65536)
        return -1;
    jsmn_init(&parser);
    j->text = text;
    j->count = jsmn_parse(&parser, text, strlen(text), j->tokens, 256);
    if (j->count < 1 || j->tokens[0].type != JSMN_OBJECT || (j->count - 1) % 2)
        return -1;
    /* These application contracts are flat objects. Check separators as well as tokens. */
    p = skip_space(text);
    if (*p++ != '{')
        return -1;
    for (i = 1; i < j->count; i += 2) {
        const jsmntok_t *k = &j->tokens[i], *v = &j->tokens[i + 1];
        if (k->type != JSMN_STRING || (v->type != JSMN_STRING && v->type != JSMN_PRIMITIVE))
            return -1;
        if (v->type == JSMN_PRIMITIVE) {
            const char *a = text + v->start, *end = text + v->end;
            size_t len = (size_t)(end - a);
            int literal = (len == 4 && !memcmp(a, "true", 4)) ||
                          (len == 5 && !memcmp(a, "false", 5)) ||
                          (len == 4 && !memcmp(a, "null", 4));
            if (!literal) {
                const char *q = a;
                if (q < end && *q == '-')
                    q++;
                if (q == end)
                    return -1;
                if (*q == '0')
                    q++;
                else {
                    if (*q < '1' || *q > '9')
                        return -1;
                    while (q < end && isdigit((unsigned char)*q))
                        q++;
                }
                if (q < end && *q == '.') {
                    q++;
                    const char *digits = q;
                    while (q < end && isdigit((unsigned char)*q))
                        q++;
                    if (q == digits)
                        return -1;
                }
                if (q < end && (*q == 'e' || *q == 'E')) {
                    q++;
                    if (q < end && (*q == '+' || *q == '-'))
                        q++;
                    const char *digits = q;
                    while (q < end && isdigit((unsigned char)*q))
                        q++;
                    if (q == digits)
                        return -1;
                }
                if (q != end)
                    return -1;
            }
        }
        p = skip_space(p);
        if (p != text + k->start - 1)
            return -1;
        p = skip_space(text + k->end + 1);
        if (*p++ != ':')
            return -1;
        p = skip_space(p);
        if (p != text + v->start - (v->type == JSMN_STRING))
            return -1;
        p = skip_space(text + v->end + (v->type == JSMN_STRING));
        if (i + 2 < j->count && *p++ != ',')
            return -1;
        for (int q = 1; q < i; q += 2) {
            if (j->tokens[q].end - j->tokens[q].start == k->end - k->start &&
                !memcmp(text + j->tokens[q].start, text + k->start, (size_t)(k->end - k->start)))
                return -1;
        }
    }
    p = skip_space(p);
    if (*p++ != '}' || *skip_space(p))
        return -1;
    return 0;
}
int json_find(const JsonObject *j, const char *key) {
    for (int i = 1; i < j->count; i += 2) {
        const jsmntok_t *t = &j->tokens[i];
        if ((size_t)(t->end - t->start) == strlen(key) &&
            !memcmp(j->text + t->start, key, strlen(key)))
            return i + 1;
    }
    return -1;
}
int json_u64(const JsonObject *j, int i, uint64_t *out) {
    uint64_t n = 0;
    if (i < 0 || i >= j->count || j->tokens[i].type != JSMN_PRIMITIVE)
        return -1;
    int a = j->tokens[i].start, b = j->tokens[i].end;
    if (a == b || (b - a > 1 && j->text[a] == '0'))
        return -1;
    for (; a < b; a++) {
        unsigned d = (unsigned)(j->text[a] - '0');
        if (d > 9 || n > (UINT64_MAX - d) / 10)
            return -1;
        n = n * 10 + d;
    }
    *out = n;
    return 0;
}
static int hex_digit(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}
int json_string(const JsonObject *j, int i, char *out, size_t capacity) {
    size_t n = 0;
    if (i < 0 || i >= j->count || j->tokens[i].type != JSMN_STRING || !capacity)
        return -1;
    for (int p = j->tokens[i].start; p < j->tokens[i].end; p++) {
        unsigned char c = (unsigned char)j->text[p];
        if (c == '\\') {
            c = (unsigned char)j->text[++p];
            if (c == 'n')
                c = '\n';
            else if (c == 'r')
                c = '\r';
            else if (c == 't')
                c = '\t';
            else if (c == 'b')
                c = '\b';
            else if (c == 'f')
                c = '\f';
            else if (c == 'u') {
                int code = 0;
                for (int q = 0; q < 4; q++) {
                    int h = hex_digit(j->text[++p]);
                    if (h < 0)
                        return -1;
                    code = code * 16 + h;
                }
                if (code < 1 || code > 127)
                    return -1;
                c = (unsigned char)code;
            } else if (c != '"' && c != '\\' && c != '/')
                return -1;
        } else if (c < 32)
            return -1;
        if (!c || n + 1 >= capacity)
            return -1;
        out[n++] = (char)c;
    }
    out[n] = 0;
    return 0;
}
int json_quote(char *out, size_t cap, const char *s) {
    size_t n = 0;
    if (cap < 3)
        return -1;
    out[n++] = '"';
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') {
            if (n + 2 >= cap)
                return -1;
            out[n++] = '\\';
            out[n++] = (char)c;
        } else if (c < 32) {
            if (n + 6 >= cap)
                return -1;
            snprintf(out + n, cap - n, "\\u%04x", c);
            n += 6;
        } else {
            if (n + 1 >= cap)
                return -1;
            out[n++] = (char)c;
        }
    }
    if (n + 2 > cap)
        return -1;
    out[n++] = '"';
    out[n] = 0;
    return (int)n;
}
int atomic_replace(const char *path, const char *data, size_t length) {
    char tmp[1024];
    FILE *f;
    int rc;
#ifdef _WIN32
    static volatile LONG serial = 0;
    int seq = (int)InterlockedIncrement(&serial);
    int pid = (int)GetCurrentProcessId();
#else
    static atomic_int serial = 0;
    int seq = atomic_fetch_add(&serial, 1);
    int pid = (int)getpid();
#endif
    if (snprintf(tmp, sizeof(tmp), "%s.%d.%d.tmp", path, pid, seq) >= (int)sizeof(tmp))
        return -1;
    f = fopen(tmp, "wb");
    if (!f)
        return -1;
    rc = fwrite(data, 1, length, f) == length && fflush(f) == 0 ? 0 : -1;
#ifdef _WIN32
    if (!rc && _commit(_fileno(f)))
        rc = -1;
#else
    if (!rc && fsync(fileno(f)))
        rc = -1;
#endif
    if (fclose(f))
        rc = -1;
    if (!rc) {
#ifdef _WIN32
        if (!MoveFileExA(tmp, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            rc = -1;
#else
        if (rename(tmp, path))
            rc = -1;
        if (!rc) {
            char parent[1024];
            snprintf(parent, sizeof(parent), "%s", path);
            char *slash = strrchr(parent, '/');
            if (slash) {
                if (slash == parent)
                    slash[1] = 0;
                else
                    *slash = 0;
            } else
                strcpy(parent, ".");
            int fd = open(parent, O_RDONLY | O_DIRECTORY);
            if (fd < 0 || fsync(fd))
                rc = -1;
            if (fd >= 0)
                close(fd);
        }
#endif
    }
    if (rc)
        remove(tmp);
    return rc;
}
