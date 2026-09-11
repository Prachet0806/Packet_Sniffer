#ifndef DB_H
#define DB_H

#ifdef HAVE_LIBPQ
#include <libpq-fe.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Connect to PostgreSQL using connection string
// Example: "host=localhost port=5432 dbname=snifferdb user=sniffer password=snifferpass"
int db_connect(const char *conninfo);

// Disconnect from PostgreSQL
void db_disconnect(void);

// Ensure required tables exist (idempotent)
int db_ensure_schema(void);

// Insert/update protocol stats in the database
int db_insert_stats(const char *proto, unsigned long count);

#ifdef __cplusplus
}
#endif

#endif // DB_H
