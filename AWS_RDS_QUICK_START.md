# AWS RDS deployment (schema v2)

Use a private/restricted RDS endpoint and a dedicated application account. Configure libpq with `sslmode=verify-full` and the appropriate CA certificate. Keep credentials out of committed files and command history.

Example environment template (replace placeholders):

```text
AWS_RDS_CONNINFO=host=YOUR-ENDPOINT port=5432 dbname=snifferdb user=sniffer_app password=YOUR-PASSWORD sslmode=verify-full sslrootcert=PATH-TO-CA
SNIFFER_SENSOR_ID=production-sensor
SNIFFER_STATE_DIR=production-state
```

Apply `db_migration_add_dhcp.sql` administratively. It creates versioned v2 tables without altering historical `protocol_stats` rows or assuming whether they use `timestamp`, `interval_start`, or protocol-per-row storage. Existing history keeps its original semantics; new Grafana queries use `protocol_stats_v2` and `alerts_v2`.

Build with PostgreSQL enabled, then run `sniffer --db-required --iface INTERFACE --state-dir production-state`. The required-database policy fails startup on connection/schema errors. Without that flag, the local journals preserve checkpointed pending events during outages. Bind the HTTP API locally behind a TLS proxy.

Use a separate read-only Grafana account. Configure sensor-specific retention explicitly with `SNIFFER_RETENTION_DAYS`; zero preserves history. Back up the database and state directory before upgrading. See README.md for counter semantics and bounded recovery guarantees.
