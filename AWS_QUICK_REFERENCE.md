# PostgreSQL/RDS reference

Canonical schema and migration: `db_migration_add_dhcp.sql`.

```sql
SELECT sensor_id, interval_start, interval_end, total_packets, duration_seconds
FROM protocol_stats_v2 ORDER BY interval_start DESC LIMIT 10;
SELECT sensor_id, SUM(total_packets) FROM protocol_stats_v2 GROUP BY sensor_id;
SELECT time, sensor_id, type, confidence, src, dst, detail
FROM alerts_v2 ORDER BY time DESC LIMIT 50;
```

`total_packets` counts captured packets once; protocol-layer counts overlap. Interval rows are deltas. JSON is cumulative and includes acknowledged watermarks for recovery. Event IDs are unique to prevent duplicate retry inserts.

Use libpq `PG*` environment variables or connection strings with `sslmode=verify-full` and a CA certificate. Connection/query deadlines are two seconds. Configure `--db-required` when missing PostgreSQL must fail startup. Never expose database credentials in source control.

Legacy tables are retained unchanged. Historical incorrectly counted totals cannot be repaired from aggregates alone. Read README.md and AWS_RDS_QUICK_START.md before upgrading or rolling back.
