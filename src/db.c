#include "db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef HAVE_LIBPQ
// Stub when built without PostgreSQL: keep API linkable, report disabled.
int db_connect(const char *conninfo) {
    (void)conninfo;
    fprintf(stderr, "[DB] Built without libpq; disabled.\n");
    return -1;
}
void db_disconnect(void) {}
int db_ensure_schema(void) { return -1; }
int db_insert_stats(const char *proto, unsigned long count) {
    (void)proto; (void)count;
    return -1;
}
#else
static PGconn *conn = NULL;

int db_connect(const char *conninfo) {
    if (!conninfo || !conninfo[0]) {
        fprintf(stderr, "[DB] No connection string; skipping.\n");
        return -1;
    }
    conn = PQconnectdb(conninfo);
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "[DB] Connection failed: %s\n", PQerrorMessage(conn));
        PQfinish(conn);
        conn = NULL;
        return -1;
    }
    printf("[DB] Connected to PostgreSQL successfully.\n");
    return 0;
}

void db_disconnect(void) {
    if (conn) {
        PQfinish(conn);
        conn = NULL;
        printf("[DB] Disconnected from PostgreSQL.\n");
    }
}

int db_ensure_schema(void) {
    if (!conn) {
        fprintf(stderr, "[DB] Connection not initialized.\n");
        return -1;
    }
    const char *ddl1 =
        "CREATE TABLE IF NOT EXISTS sniffer_stats("
        "id SERIAL PRIMARY KEY, protocol VARCHAR(32) NOT NULL,"
        "count BIGINT NOT NULL, updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP);";
    const char *ddl2 =
        "CREATE TABLE IF NOT EXISTS protocol_stats("
        "id SERIAL PRIMARY KEY, interval_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
        "total_packets BIGINT, total_bytes BIGINT,"
        "ethernet BIGINT, ethernet_bytes BIGINT, ipv4 BIGINT, ipv4_bytes BIGINT,"
        "ipv6 BIGINT, ipv6_bytes BIGINT, tcp BIGINT, tcp_bytes BIGINT,"
        "udp BIGINT, udp_bytes BIGINT, icmp BIGINT, icmp_bytes BIGINT,"
        "arp BIGINT, arp_bytes BIGINT, dns BIGINT, dns_bytes BIGINT,"
        "http BIGINT, http_bytes BIGINT, https BIGINT, https_bytes BIGINT,"
        "dhcp BIGINT, dhcp_bytes BIGINT);";
    PGresult *r = PQexec(conn, ddl1);
    if (PQresultStatus(r) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[DB] Schema ensure failed: %s\n", PQerrorMessage(conn));
        PQclear(r);
        return -1;
    }
    PQclear(r);
    r = PQexec(conn, ddl2);
    if (PQresultStatus(r) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[DB] Schema ensure failed: %s\n", PQerrorMessage(conn));
        PQclear(r);
        return -1;
    }
    PQclear(r);
    return 0;
}

int db_insert_stats(const char *proto, unsigned long count) {
    if (!conn) {
        fprintf(stderr, "[DB] Connection not initialized.\n");
        return -1;
    }
    if (!proto || !proto[0] || strlen(proto) > 31) {
        fprintf(stderr, "[DB] Bad protocol name.\n");
        return -1;
    }

    // Parameterized: no SQL injection via proto
    char countbuf[32];
    snprintf(countbuf, sizeof(countbuf), "%lu", count);
    const char *params[2] = { proto, countbuf };
    PGresult *res = PQexecParams(conn,
        "INSERT INTO sniffer_stats (protocol, count) VALUES ($1, $2::bigint);",
        2, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[DB] Insert failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }

    PQclear(res);
    return 0;
}
#endif // HAVE_LIBPQ
