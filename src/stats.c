#include "stats.h"
#include "stats_fields.h"
#include "util.h"
#include "db.h"
#include "logger.h"
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#endif
ProtocolStats stats;
#ifdef _WIN32
CRITICAL_SECTION stats_cs;
static HANDLE state_lock = INVALID_HANDLE_VALUE;
#else
pthread_mutex_t stats_cs;
static int state_lock = -1;
#endif
static mutex_t io_cs;
static thread_t worker;
static int started, initialized, batch_ms = 60000;
static atomic_flag_t stop_flag, healthy, failed;
static char conninfo[4096], snapshot_path[1024], pending_path[1024], alert_path[1024];
static char sensor[128], session[96], pending_id[160], pending_session[96], pending_sensor[128];
static uint64_t sequence;
static int64_t interval_start, pending_start, pending_end, capture_begin, capture_end;
static ProtocolStats acknowledged, pending, pending_target;
static int has_pending;
#define ALERT_MAX 256
/* Bounded pending cache, checkpointed by the worker. Saturation is observable. */
typedef struct {
    char id[160], session[96], sensor[128], time[40], type[32], src[64], dst[64], detail[192];
} StoredAlert;
static StoredAlert alerts[ALERT_MAX];
static int alert_count;
static int64_t wall_us(void) {
#ifdef _WIN32
    FILETIME f;
    ULARGE_INTEGER n;
    GetSystemTimeAsFileTime(&f);
    n.LowPart = f.dwLowDateTime;
    n.HighPart = f.dwHighDateTime;
    return (int64_t)(n.QuadPart / 10 - 11644473600000000ULL);
#else
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    return (int64_t)t.tv_sec * 1000000 + t.tv_nsec / 1000;
#endif
}
static void lock(void) { mutex_lock(&stats_cs); }
static void unlock(void) { mutex_unlock(&stats_cs); }
void stats_snapshot(ProtocolStats *out) {
    lock();
    *out = stats;
    unlock();
}
int stats_db_healthy(void) { return flag_get(&healthy); }
void stats_capture_at(uint32_t cap, uint32_t wire, int64_t ts) {
    lock();
    stats.total_packets++;
    stats.total_bytes += cap;
    stats.wire_bytes += wire;
    if (!capture_begin || ts < capture_begin)
        capture_begin = ts;
    if (ts > capture_end)
        capture_end = ts;
    unlock();
}
void stats_capture(uint32_t cap, uint32_t wire) { stats_capture_at(cap, wire, wall_us()); }
int stats_health_json(char *out, int size) {
    lock();
    int n = alert_count;
    uint64_t drops = stats.alert_drops;
    unlock();
    return snprintf(out, (size_t)size,
                    "{\"database_configured\":%s,\"database_healthy\":%s,\"local_write_failed\":%s,"
                    "\"pending_alerts\":%d,\"alert_drops\":%llu}",
                    conninfo[0] ? "true" : "false", flag_get(&healthy) ? "true" : "false",
                    flag_get(&failed) ? "true" : "false", n, (unsigned long long)drops);
}
void stats_note(const char *kind) {
    lock();
#define NOTE(name)                                                                                 \
    if (!strcmp(kind, #name)) {                                                                    \
        stats.name++;                                                                              \
        unlock();                                                                                  \
        return;                                                                                    \
    }
    NOTE(analyzed)
    NOTE(queue_drops)
    NOTE(allocation_drops)
    NOTE(recording_errors)
    NOTE(malformed)
    NOTE(truncated) NOTE(unsupported) NOTE(incomplete) NOTE(alert_drops) NOTE(state_evictions)
#undef NOTE
        unlock();
}
void stats_increment(const char *proto, uint32_t bytes) {
    lock();
#define INC(text, name)                                                                            \
    if (!strcmp(proto, text)) {                                                                    \
        stats.name++;                                                                              \
        stats.name##_bytes += bytes;                                                               \
        unlock();                                                                                  \
        return;                                                                                    \
    }
    INC("ETH", ethernet)
    INC("IPv4", ipv4)
    INC("IPv6", ipv6)
    INC("TCP", tcp)
    INC("UDP", udp)
    INC("ICMP", icmp) INC("ARP", arp) INC("DNS", dns) INC("HTTP", http) INC("HTTPS", https)
        INC("DHCP", dhcp)
#undef INC
            unlock();
}
static int add_fields(char *out, size_t cap, size_t *pos, const ProtocolStats *s,
                      const char *prefix) {
#define FIELD(name)                                                                                \
    do {                                                                                           \
        int n = snprintf(out + *pos, cap - *pos, ",\"%s" #name "\":%" PRIu64, prefix, s->name);    \
        if (n < 0 || (size_t)n >= cap - *pos)                                                      \
            return -1;                                                                             \
        *pos += (size_t)n;                                                                         \
    } while (0);
    STATS_FIELDS(FIELD)
#undef FIELD
    return 0;
}
int stats_format_json(char *out, int cap, const ProtocolStats *s, int pretty) {
    (void)pretty;
    if (!out || cap < 4)
        return -1;
    size_t p = 0;
    int n = snprintf(out, (size_t)cap, "{\"schema_version\":2");
    if (n < 0 || n >= cap)
        return -1;
    p = (size_t)n;
    if (add_fields(out, (size_t)cap, &p, s, ""))
        return -1;
    if (p + 2 > (size_t)cap)
        return -1;
    out[p++] = '}';
    out[p] = 0;
    return (int)p;
}
static int load_fields(const JsonObject *j, ProtocolStats *out, const char *prefix, int required) {
    char key[96];
    memset(out, 0, sizeof(*out));
#define LOAD(name)                                                                                 \
    do {                                                                                           \
        snprintf(key, sizeof(key), "%s" #name, prefix);                                            \
        int t = json_find(j, key);                                                                 \
        if (t < 0) {                                                                               \
            if (required)                                                                          \
                return -1;                                                                         \
        } else if (json_u64(j, t, &out->name))                                                     \
            return -1;                                                                             \
    } while (0);
    STATS_FIELDS(LOAD)
#undef LOAD
    return 0;
}
static char *read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END)) {
        fclose(f);
        return NULL;
    }
    long size = ftell(f);
    if (size < 0 || size > 65536) {
        fclose(f);
        errno = EINVAL;
        return NULL;
    }
    rewind(f);
    char *b = malloc((size_t)size + 1);
    if (!b) {
        fclose(f);
        return NULL;
    }
    if (fread(b, 1, (size_t)size, f) != (size_t)size) {
        free(b);
        fclose(f);
        return NULL;
    }
    if (memchr(b, 0, (size_t)size)) {
        free(b);
        fclose(f);
        errno = EINVAL;
        return NULL;
    }
    b[size] = 0;
    fclose(f);
    return b;
}
int stats_load_json(const char *path) {
    mutex_lock(&io_cs);
    char *b = read_file(path);
    if (!b) {
        int rc = errno == ENOENT ? 1 : -1;
        mutex_unlock(&io_cs);
        return rc;
    }
    JsonObject j;
    ProtocolStats s = {0}, a = {0};
    uint64_t version = 0;
    int rc = json_parse(&j, b);
    if (!rc) {
        int t = json_find(&j, "schema_version");
        if (t >= 0)
            rc = json_u64(&j, t, &version);
    }
    if (!rc && version != 0 && version != 2)
        rc = -1;
    if (!rc)
        rc = load_fields(&j, &s, "", version == 2);
    if (!rc && version == 2)
        rc = load_fields(&j, &a, "ack_", 1);
    if (!rc && version == 2) {
#define VERIFY(name)                                                                               \
    if (a.name > s.name)                                                                           \
        rc = -1;
        STATS_FIELDS(VERIFY)
#undef VERIFY
        char saved_sensor[128];
        if (json_string(&j, json_find(&j, "sensor_id"), saved_sensor, sizeof(saved_sensor)) ||
            strcmp(saved_sensor, sensor))
            rc = -1;
    }
    if (!rc) {
        lock();
        if (version == 2) {
            stats = s;
            acknowledged = a;
        } else {
            memset(&stats, 0, sizeof(stats));
            memset(&acknowledged, 0, sizeof(acknowledged));
        }
        unlock();
    }
    if (!rc && version == 0) {
        char legacy[1100];
        snprintf(legacy, sizeof(legacy), "%s.legacy", path);
        char *old = read_file(legacy);
        int identical = old && !strcmp(old, b);
        if (old && !identical)
            snprintf(legacy, sizeof(legacy), "%s.legacy.%lld", path, (long long)wall_us());
        free(old);
        if (!identical && atomic_replace(legacy, b, strlen(b)))
            rc = -1;
        LOG_WARN_MSG("Archived legacy counters in %.900s; starting corrected counters from zero\n",
                     legacy);
    }
    free(b);
    mutex_unlock(&io_cs);
    return rc;
}
static int checkpoint(const char *path) {
    char b[16384];
    size_t p;
    ProtocolStats s;
    stats_snapshot(&s);
    int n = stats_format_json(b, sizeof(b), &s, 0);
    if (n < 0)
        return -1;
    p = (size_t)n - 1;
    if (add_fields(b, sizeof(b), &p, &acknowledged, "ack_"))
        return -1;
    char q[512];
    if (json_quote(q, sizeof(q), sensor) < 0)
        return -1;
    n = snprintf(b + p, sizeof(b) - p, ",\"sensor_id\":%s}", q);
    if (n < 0 || (size_t)n >= sizeof(b) - p)
        return -1;
    p += (size_t)n;
    return atomic_replace(path, b, p);
}
int stats_save_json(const char *path) {
    mutex_lock(&io_cs);
    int r = checkpoint(path);
    mutex_unlock(&io_cs);
    return r;
}
static int pending_write(void) {
    char b[16384], ei[400], se[256], sn[300];
    int n = stats_format_json(b, sizeof(b), &pending, 0);
    if (n < 0)
        return -1;
    size_t pos = (size_t)n - 1;
    if (add_fields(b, sizeof(b), &pos, &pending_target, "target_"))
        return -1;
    b[pos++] = '}';
    b[pos] = 0;
    n = (int)pos;
    if (json_quote(ei, sizeof(ei), pending_id) < 0 ||
        json_quote(se, sizeof(se), pending_session) < 0 ||
        json_quote(sn, sizeof(sn), pending_sensor) < 0)
        return -1;
    int m = snprintf(
        b + n - 1, sizeof(b) - (size_t)n + 1,
        ",\"event_id\":%s,\"session_id\":%s,\"sensor_id\":%s,\"begin_us\":%lld,\"end_us\":%lld}",
        ei, se, sn, (long long)pending_start, (long long)pending_end);
    if (m < 0 || (size_t)m >= sizeof(b) - (size_t)n + 1)
        return -1;
    return atomic_replace(pending_path, b, (size_t)n - 1 + (size_t)m);
}
static int pending_read(void) {
    char *b = read_file(pending_path);
    if (!b)
        return errno == ENOENT ? 0 : -1;
    JsonObject j;
    uint64_t begin = 0, end = 0, version = 0;
    int rc =
        json_parse(&j, b) || json_u64(&j, json_find(&j, "schema_version"), &version) ||
        load_fields(&j, &pending, "", 1) || load_fields(&j, &pending_target, "target_", 1) ||
        json_string(&j, json_find(&j, "event_id"), pending_id, sizeof(pending_id)) ||
        json_string(&j, json_find(&j, "session_id"), pending_session, sizeof(pending_session)) ||
        json_string(&j, json_find(&j, "sensor_id"), pending_sensor, sizeof(pending_sensor)) ||
        json_u64(&j, json_find(&j, "begin_us"), &begin) ||
        json_u64(&j, json_find(&j, "end_us"), &end);
    if (version != 2 || begin > INT64_MAX || end > INT64_MAX || end < begin ||
        strcmp(pending_sensor, sensor) || !pending_id[0] || !pending_session[0])
        rc = -1;
    if (!rc) {
        int before_ack = 1, after_ack = 1;
#define VERIFY_PENDING(name)                                                                       \
    do {                                                                                           \
        if (pending.name > pending_target.name)                                                    \
            rc = -1;                                                                               \
        else if (acknowledged.name != pending_target.name - pending.name)                          \
            before_ack = 0;                                                                        \
        if (acknowledged.name != pending_target.name)                                              \
            after_ack = 0;                                                                         \
    } while (0);
        STATS_FIELDS(VERIFY_PENDING)
#undef VERIFY_PENDING
        if (!before_ack && !after_ack)
            rc = -1;
    }
    if (!rc) {
        pending_start = (int64_t)begin;
        pending_end = (int64_t)end;
        has_pending = 1;
#define FLOOR(name)                                                                                \
    if (stats.name < pending_target.name)                                                          \
        stats.name = pending_target.name;
        STATS_FIELDS(FLOOR)
#undef FLOOR
    }
    free(b);
    return rc ? -1 : 0;
}
void stats_queue_alert(const char *t, const char *y, const char *s, const char *d, const char *v) {
    lock();
    if (alert_count == ALERT_MAX) {
        stats.alert_drops++;
        unlock();
        return;
    }
    StoredAlert *a = &alerts[alert_count++];
    snprintf(a->id, sizeof(a->id), "%s-a%" PRIu64, session, ++sequence);
    snprintf(a->session, sizeof(a->session), "%s", session);
    snprintf(a->sensor, sizeof(a->sensor), "%s", sensor);
    snprintf(a->time, sizeof(a->time), "%s", t);
    snprintf(a->type, sizeof(a->type), "%s", y);
    snprintf(a->src, sizeof(a->src), "%s", s);
    snprintf(a->dst, sizeof(a->dst), "%s", d);
    snprintf(a->detail, sizeof(a->detail), "%s", v);
    unlock();
}
static int alert_save(void) {
    char b[256 * 1800];
    size_t p = 0;
    lock();
    for (int i = 0; i < alert_count; i++) {
        StoredAlert *a = &alerts[i];
        char q[8][1024];
        const char *v[] = {a->id,   a->sensor, a->session, a->time,
                           a->type, a->src,    a->dst,     a->detail};
        for (int k = 0; k < 8; k++)
            if (json_quote(q[k], sizeof(q[k]), v[k]) < 0) {
                unlock();
                return -1;
            }
        int n = snprintf(b + p, sizeof(b) - p,
                         "{\"event_id\":%s,\"sensor_id\":%s,\"session_id\":%s,\"time\":%s,\"type\":"
                         "%s,\"src\":%s,\"dst\":%s,\"detail\":%s}\n",
                         q[0], q[1], q[2], q[3], q[4], q[5], q[6], q[7]);
        if (n < 0 || (size_t)n >= sizeof(b) - p) {
            unlock();
            return -1;
        }
        p += (size_t)n;
    }
    unlock();
    return atomic_replace(alert_path, b, p);
}
static int alert_load(void) {
    FILE *f = fopen(alert_path, "rb");
    if (!f)
        return errno == ENOENT ? 0 : -1;
    char b[2048];
    while (fgets(b, sizeof(b), f)) {
        if (alert_count == ALERT_MAX) {
            fclose(f);
            return -1;
        }
        JsonObject j;
        StoredAlert *a = &alerts[alert_count];
        const char *k[] = {"event_id", "sensor_id", "session_id", "time",
                           "type",     "src",       "dst",        "detail"};
        char *v[] = {a->id, a->sensor, a->session, a->time, a->type, a->src, a->dst, a->detail};
        size_t caps[] = {sizeof(a->id),   sizeof(a->sensor), sizeof(a->session), sizeof(a->time),
                         sizeof(a->type), sizeof(a->src),    sizeof(a->dst),     sizeof(a->detail)};
        if (json_parse(&j, b)) {
            fclose(f);
            return -1;
        }
        for (int i = 0; i < 8; i++)
            if (json_string(&j, json_find(&j, k[i]), v[i], caps[i])) {
                fclose(f);
                return -1;
            }
        if (strcmp(a->sensor, sensor) || !a->id[0] || !a->session[0]) {
            fclose(f);
            return -1;
        }
        alert_count++;
    }
    int rc = ferror(f) ? -1 : 0;
    fclose(f);
    return rc;
}
int stats_save_postgres(const char *ignored) {
    (void)ignored; /* worker only */
    if (!conninfo[0])
        return 0;
    if (!has_pending) {
        ProtocolStats s;
        stats_snapshot(&s);
#define DELTA(name) pending.name = s.name - acknowledged.name;
        STATS_FIELDS(DELTA)
#undef DELTA
        pending_target = s;
        pending_start = interval_start;
        pending_end = wall_us();
        const char *rp = getenv("SNIFFER_READ");
        if (rp && *rp) {
            lock();
            if (capture_begin) {
                pending_start = capture_begin;
                pending_end = capture_end;
            }
            unlock();
            if (pending_end <= pending_start)
                pending_end = pending_start + 1000;
        }
        lock();
        uint64_t event_sequence = ++sequence;
        unlock();
        snprintf(pending_id, sizeof(pending_id), "%s-s%" PRIu64, session, event_sequence);
        snprintf(pending_session, sizeof(pending_session), "%s", session);
        snprintf(pending_sensor, sizeof(pending_sensor), "%s", sensor);
        has_pending = 1;
    }
    if (pending_write() || checkpoint(snapshot_path) || alert_save()) {
        flag_set(&failed, 1);
        return -1;
    }
    if (!flag_get(&healthy)) {
        if (db_connect(conninfo) || db_ensure_schema()) {
            flag_set(&healthy, 0);
            return -1;
        }
        flag_set(&healthy, 1);
    }
    if (db_write_stats(pending_id, pending_sensor, pending_session, pending_start, pending_end,
                       &pending)) {
        db_disconnect();
        flag_set(&healthy, 0);
        return -1;
    }
#define ACK(name) acknowledged.name = pending_target.name;
    STATS_FIELDS(ACK)
#undef ACK
    /* A committed batch stays in the journal until its acknowledgement is checkpointed. */
    if (checkpoint(snapshot_path)) {
        flag_set(&failed, 1);
        return -1;
    }
    if (remove(pending_path) && errno != ENOENT) {
        flag_set(&failed, 1);
        return -1;
    }
    has_pending = 0;
    interval_start = pending_end;
    for (;;) {
        StoredAlert a;
        lock();
        int count = alert_count;
        if (count)
            a = alerts[0];
        unlock();
        if (!count)
            break;
        if (db_write_alert(a.id, a.sensor, a.session, a.time, a.type, a.src, a.dst, a.detail)) {
            db_disconnect();
            flag_set(&healthy, 0);
            break;
        }
        lock();
        memmove(alerts, alerts + 1, (size_t)(--alert_count) * sizeof(*alerts));
        unlock();
    }
    if (alert_save())
        flag_set(&failed, 1);
    return 0;
}
#ifdef _WIN32
DWORD WINAPI stats_batch_thread(LPVOID unused) {
#else
void *stats_batch_thread(void *unused) {
#endif
    (void)unused;
    uint64_t next = monotonic_ms() + (unsigned)batch_ms;
    if (conninfo[0]) {
        if (!db_connect(conninfo) && !db_ensure_schema()) {
            flag_set(&healthy, 1);
            long days;
            if (!env_integer("SNIFFER_RETENTION_DAYS", 0, 0, 36500, &days) && days)
                db_retention(sensor, days);
        }
    }
    while (!flag_get(&stop_flag)) {
        sleep_ms(50);
        if (monotonic_ms() < next)
            continue;
        mutex_lock(&io_cs);
        if (conninfo[0])
            stats_save_postgres(NULL);
        else if (checkpoint(snapshot_path) || alert_save())
            flag_set(&failed, 1);
        mutex_unlock(&io_cs);
        next = monotonic_ms() + (unsigned)batch_ms;
    }
    mutex_lock(&io_cs);
    if (conninfo[0]) {
        stats_save_postgres(NULL);
        if (flag_get(&healthy) && !has_pending)
            stats_save_postgres(NULL);
    }
    if (checkpoint(snapshot_path) || alert_save())
        flag_set(&failed, 1);
    db_disconnect();
    mutex_unlock(&io_cs);
    return 0;
}
int stats_init(const char *info) {
    long ms;
    char replay_dir[96];
    const char *dir = getenv("SNIFFER_STATE_DIR");
    const char *read_mode = getenv("SNIFFER_READ");
    if (!dir && read_mode && read_mode[0]) {
        snprintf(replay_dir, sizeof(replay_dir), ".replay-%lld", (long long)wall_us());
        dir = replay_dir;
    }
    if (!dir)
        dir = ".";
    if (initialized || env_integer("STATS_FLUSH_MS", 60000, 1000, 3600000, &ms))
        return -1;
    batch_ms = (int)ms;
    if (info && strlen(info) >= sizeof(conninfo))
        return -1;
    snprintf(conninfo, sizeof(conninfo), "%s", info ? info : "");
    const char *sn = getenv("SNIFFER_SENSOR_ID");
    if (sn && strlen(sn) >= sizeof(sensor))
        return -1;
    snprintf(sensor, sizeof(sensor), "%s", sn ? sn : "default");
    if (snprintf(snapshot_path, sizeof(snapshot_path), "%s/stats.json", dir) >=
        (int)sizeof(snapshot_path))
        return -1;
    snprintf(pending_path, sizeof(pending_path), "%s/pending-stats.json", dir);
    snprintf(alert_path, sizeof(alert_path), "%s/pending-alerts.jsonl", dir);
    char lp[1100];
    snprintf(lp, sizeof(lp), "%s/.sniffer.lock", dir);
#ifdef _WIN32
    if (strcmp(dir, ".") && _mkdir(dir) && errno != EEXIST)
        return -1;
    state_lock = CreateFileA(lp, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL, NULL);
    if (state_lock == INVALID_HANDLE_VALUE)
        return -1;
    unsigned long pid = GetCurrentProcessId();
#else
    if (strcmp(dir, ".") && mkdir(dir, 0700) && errno != EEXIST)
        return -1;
    state_lock = open(lp, O_CREAT | O_RDWR, 0600);
    if (state_lock < 0)
        return -1;
    if (flock(state_lock, LOCK_EX | LOCK_NB)) {
        close(state_lock);
        state_lock = -1;
        return -1;
    }
    unsigned long pid = (unsigned long)getpid();
#endif
    mutex_init(&stats_cs);
    mutex_init(&io_cs);
    initialized = 1;
    memset(&stats, 0, sizeof(stats));
    memset(&acknowledged, 0, sizeof(acknowledged));
    flag_set(&stop_flag, 0);
    flag_set(&healthy, 0);
    flag_set(&failed, 0);
    alert_count = 0;
    has_pending = 0;
    sequence = 0;
    capture_begin = capture_end = 0;
    interval_start = wall_us();
    snprintf(session, sizeof(session), "%lld-%lu-%llu", (long long)interval_start, pid,
             (unsigned long long)monotonic_ms());
    /* Replay state lives in an explicitly selected directory; no automatic import of live counters.
     */
    const char *rp = getenv("SNIFFER_READ");
    if ((!(rp && rp[0]) || getenv("SNIFFER_STATE_DIR")) && stats_load_json(snapshot_path) < 0) {
        stats_cleanup();
        return -1;
    }
    if (pending_read() || alert_load()) {
        stats_cleanup();
        return -1;
    }
#ifdef _WIN32
    worker = CreateThread(NULL, 0, stats_batch_thread, NULL, 0, NULL);
    if (!worker) {
        stats_cleanup();
        return -1;
    }
#else
    if (pthread_create(&worker, NULL, stats_batch_thread, NULL)) {
        stats_cleanup();
        return -1;
    }
#endif
    started = 1;
    return 0;
}
int stats_cleanup(void) {
    if (!initialized)
        return 0;
    flag_set(&stop_flag, 1);
    if (started) {
#ifdef _WIN32
        WaitForSingleObject(worker, INFINITE);
        CloseHandle(worker);
#else
        pthread_join(worker, NULL);
#endif
        started = 0;
    }
    mutex_destroy(&io_cs);
    mutex_destroy(&stats_cs);
    initialized = 0;
#ifdef _WIN32
    CloseHandle(state_lock);
    state_lock = INVALID_HANDLE_VALUE;
#else
    close(state_lock);
    state_lock = -1;
#endif
    return flag_get(&failed) ? -1 : 0;
}
