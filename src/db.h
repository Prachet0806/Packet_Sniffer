#ifndef DB_H
#define DB_H
#include "stats.h"
int db_connect(const char *conninfo);
void db_disconnect(void);
int db_ensure_schema(void);
int db_retention(const char *sensor, long days);
int db_write_stats(const char *event, const char *sensor, const char *session, int64_t begin,
                   int64_t end, const ProtocolStats *s);
int db_write_alert(const char *event, const char *sensor, const char *session, const char *time,
                   const char *type, const char *src, const char *dst, const char *detail);
#endif
