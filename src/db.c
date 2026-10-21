#include "db.h"
#include "util.h"
#include "stats_fields.h"
#include "logger.h"
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#ifdef HAVE_LIBPQ
#include <libpq-fe.h>
#include "schema_sql.h"
static PGconn *conn;
/* Only the persistence worker calls this module. All libpq operations have deadlines. */
static int ready(PGconn *c, int writing, uint64_t deadline) {
    int fd = PQsocket(c);
    while (monotonic_ms() < deadline) {
        fd_set rd, wr;
        struct timeval tv = {0, 100000};
        FD_ZERO(&rd);
        FD_ZERO(&wr);
        if (writing)
            FD_SET(fd, &wr);
        else
            FD_SET(fd, &rd);
        int n = select(fd + 1, &rd, &wr, NULL, &tv);
        if (n > 0)
            return 0;
        if (n < 0)
            return -1;
    }
    return -1;
}
int db_connect(const char *info) {
    db_disconnect();
    conn = PQconnectStart(info);
    if (!conn)
        return -1;
    uint64_t end = monotonic_ms() + 2000;
    for (;;) {
        PostgresPollingStatusType s = PQconnectPoll(conn);
        if (s == PGRES_POLLING_OK)
            break;
        if (s == PGRES_POLLING_FAILED || ready(conn, s == PGRES_POLLING_WRITING, end)) {
            db_disconnect();
            return -1;
        }
    }
    if (PQsetnonblocking(conn, 1)) {
        db_disconnect();
        return -1;
    }
    return 0;
}
void db_disconnect(void) {
    if (conn) {
        PQfinish(conn);
        conn = NULL;
    }
}
static int query(const char *sql, int n, const char *const *params) {
    if (!conn || !PQsendQueryParams(conn, sql, n, NULL, params, NULL, NULL, 0))
        return -1;
    uint64_t end = monotonic_ms() + 2000;
    int f;
    while ((f = PQflush(conn)) == 1)
        if (ready(conn, 1, end)) {
            db_disconnect();
            return -1;
        }
    if (f < 0) {
        db_disconnect();
        return -1;
    }
    while (PQisBusy(conn)) {
        if (ready(conn, 0, end) || !PQconsumeInput(conn)) {
            db_disconnect();
            return -1;
        }
    }
    int ok = 0;
    PGresult *r;
    while ((r = PQgetResult(conn)) != NULL) {
        ExecStatusType s = PQresultStatus(r);
        if (s != PGRES_COMMAND_OK && s != PGRES_TUPLES_OK)
            ok = -1;
        PQclear(r);
    }
    return ok;
}
static int schema_ready(void) {
    char columns[2048] = "SELECT event_id,sensor_id,session_id,interval_start,interval_end,"
                         "duration_seconds";
#define CHECK_COLUMN(name) strcat(columns, "," #name);
    STATS_FIELDS(CHECK_COLUMN)
#undef CHECK_COLUMN
    strcat(columns, " FROM protocol_stats_v2 LIMIT 0");
    return !query("SELECT 1 / COUNT(*)::integer FROM sniffer_schema WHERE version=2", 0, NULL) &&
           !query(columns, 0, NULL) &&
           !query(
               "SELECT event_id,sensor_id,session_id,time,type,src,dst,detail,severity,confidence "
               "FROM alerts_v2 LIMIT 0",
               0, NULL);
}
int db_ensure_schema(void) {
    /* A pre-migrated deployment needs read/insert privileges, not runtime DDL privileges. */
    if (schema_ready())
        return 0;
    /* PQsendQuery permits the transaction's multiple DDL statements. */
    if (!conn || !PQsendQuery(conn, schema_sql))
        return -1;
    uint64_t end = monotonic_ms() + 2000;
    int f;
    while ((f = PQflush(conn)) == 1)
        if (ready(conn, 1, end)) {
            db_disconnect();
            return -1;
        }
    if (f < 0) {
        db_disconnect();
        return -1;
    }
    int ok = 0;
    for (;;) {
        while (PQisBusy(conn))
            if (ready(conn, 0, end) || !PQconsumeInput(conn)) {
                db_disconnect();
                return -1;
            }
        PGresult *r = PQgetResult(conn);
        if (!r)
            break;
        if (PQresultStatus(r) != PGRES_COMMAND_OK)
            ok = -1;
        PQclear(r);
    }
    if (ok) {
        query("ROLLBACK", 0, NULL);
        return -1;
    }
    return schema_ready() ? 0 : -1;
}
int db_retention(const char *sensor, long days) {
    if (!days)
        return 0;
    char d[32];
    snprintf(d, sizeof(d), "%ld", days);
    const char *args[] = {sensor, d};
    if (query("DELETE FROM protocol_stats_v2 WHERE sensor_id=$1 AND interval_end < "
              "NOW()-($2::integer * INTERVAL '1 day')",
              2, args))
        return -1;
    return query("DELETE FROM alerts_v2 WHERE sensor_id=$1 AND time < NOW()-($2::integer * "
                 "INTERVAL '1 day')",
                 2, args);
}
int db_write_stats(const char *event, const char *sensor, const char *session, int64_t begin,
                   int64_t end, const ProtocolStats *s) {
    char sql[4096] = "INSERT INTO "
                     "protocol_stats_v2(event_id,sensor_id,session_id,interval_start,interval_end,"
                     "duration_seconds";
#define COL(name) strcat(sql, "," #name);
    STATS_FIELDS(COL)
#undef COL
    strcat(
        sql,
        ") VALUES($1,$2,$3,to_timestamp($4::double precision/1000000),to_timestamp($5::double "
        "precision/1000000),GREATEST(($5::double precision-$4::double precision)/1000000,0.001)");
    char nums[40][32], b[32], e[32];
    const char *args[40] = {event, sensor, session, b, e};
    int n = 5;
    snprintf(b, sizeof(b), "%lld", (long long)begin);
    snprintf(e, sizeof(e), "%lld", (long long)end);
#define VALUE(name)                                                                                \
    do {                                                                                           \
        if (s->name > INT64_MAX)                                                                   \
            return -1;                                                                             \
        snprintf(nums[n], sizeof(nums[n]), "%" PRIu64, s->name);                                   \
        args[n] = nums[n];                                                                         \
        char ph[16];                                                                               \
        snprintf(ph, sizeof(ph), ",$%d::bigint", n + 1);                                           \
        strcat(sql, ph);                                                                           \
        n++;                                                                                       \
    } while (0);
    STATS_FIELDS(VALUE)
#undef VALUE
    strcat(sql, ") ON CONFLICT(event_id) DO NOTHING");
    return query(sql, n, args);
}
int db_write_alert(const char *event, const char *sensor, const char *session, const char *time,
                   const char *type, const char *src, const char *dst, const char *detail) {
    const char *a[] = {event, sensor, session, time, type, src, dst, detail};
    return query("INSERT INTO alerts_v2(event_id,sensor_id,session_id,time,type,src,dst,detail) "
                 "VALUES($1,$2,$3,$4::timestamptz,$5,$6,$7,$8) ON CONFLICT(event_id) DO NOTHING",
                 8, a);
}
#else
int db_connect(const char *c) {
    (void)c;
    return -1;
}
void db_disconnect(void) {}
int db_ensure_schema(void) { return -1; }
int db_retention(const char *s, long d) {
    (void)s;
    (void)d;
    return -1;
}
int db_write_stats(const char *e, const char *n, const char *i, int64_t b, int64_t z,
                   const ProtocolStats *s) {
    (void)e;
    (void)n;
    (void)i;
    (void)b;
    (void)z;
    (void)s;
    return -1;
}
int db_write_alert(const char *e, const char *n, const char *i, const char *t, const char *y,
                   const char *s, const char *d, const char *v) {
    (void)e;
    (void)n;
    (void)i;
    (void)t;
    (void)y;
    (void)s;
    (void)d;
    (void)v;
    return -1;
}
#endif
