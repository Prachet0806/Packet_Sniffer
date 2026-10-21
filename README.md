# Packet Sniffer and Protocol Analyzer

A C11 packet-capture pipeline for libpcap/Npcap with bounded queues, protocol observations, cumulative JSON statistics, optional PostgreSQL interval storage, a local HTTP API, and Grafana provisioning.

## Build and verify

Requirements: CMake 3.16+, C11 compiler, libpcap development files or the Npcap SDK/runtime, and Python 3 for tests. PostgreSQL client headers/libraries are optional.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Windows: use MSVC, set `NPCAP_SDK` to the SDK root, and optionally set `PostgreSQL_ROOT` to your PostgreSQL installation. Runtime DLLs are staged with architecture validation. Use `-DSNIFFER_POSTGRES=OFF` for an explicit JSON-only build. Use `-DBUILD_TESTING=OFF` for production builds without Python/test sources.

Linux sanitizer verification:

```sh
cmake -S . -B build-asan -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Debug -DSNIFFER_SANITIZERS=ON
cmake --build build-asan
ctest --test-dir build-asan --output-on-failure
```

## Capture and replay

```sh
# Offline replay: no capture privileges, isolated automatically generated .replay-* state
./build/sniffer --no-env --read tests/pcaps/eth-tcp-http.pcap --no-db --quiet
# Explicit state directory (exclusive ownership); repeated runs resume its cumulative totals
./build/sniffer --no-env --read tests/pcaps/dns.pcap --state-dir replay-state --no-db
# Native live capture: exact interface name or unique substring/index
./build/sniffer --iface eth0 --filter 'tcp and (port 80 or port 443)' --state-dir live-state
# Packet details are DEBUG output
./build/sniffer --iface eth0 --log-level 3 --write capture.pcap
```

Capture requires appropriate operating-system privileges. An invalid filter, missing input, ambiguous interface, or recording-open failure exits nonzero. SIGINT/SIGTERM/Ctrl+C request orderly shutdown. A live loop polls pcap nonblocking so idle traffic does not prevent command handling or shutdown.

Fragmented IPv4/IPv6 packets are counted at the network layer and marked incomplete; there is no IP fragment reassembly. Supported links: Ethernet/VLAN (up to eight tags), NULL/LOOP, SLL, genuine SLL2, and raw IP. Unsupported links are explicitly counted, never guessed as Ethernet.

## Configuration

Precedence: CLI, process environment, `.env`, defaults. `--no-env` disables loading the working directory's `.env`. CLI numeric arguments and environment numeric settings reject malformed/out-of-range values.

| Setting | Default / meaning |
|---|---|
| `SNIFFER_IFACE`, `SNIFFER_FILTER` | Interface and pcap BPF |
| `SNIFFER_READ`, `SNIFFER_WRITE` | Offline input/live recording; mutually exclusive |
| `SNIFFER_STATE_DIR` | `.` for live; unique `.replay-*` for replay unless explicitly set |
| `SNIFFER_SENSOR_ID` | `default`; must match an existing versioned state directory |
| `SNIFFER_SNAPLEN` | 65536; accepted range 68–262144 |
| `SNIFFER_TIMEOUT_MS` | 1000; accepted range 10–60000 |
| `SNIFFER_PROMISC` | 1; 0 disables promiscuous mode |
| `SNIFFER_QUEUE_BYTES` | 64 MiB; accepted range 256 KiB–1 GiB |
| `STATS_FLUSH_MS` | 60000; accepted range 1000–3600000 |
| `LOG_LEVEL` / `--log-level` | 0 error, 1 warning, 2 info, 3 packet detail |
| `SNIFFER_SYN_THRESHOLD` | 20 distinct destination/port pairs per source in 60 seconds |
| `SNIFFER_DHCP_THRESHOLD` | 32 distinct client transactions in 10 seconds |
| `SNIFFER_RETENTION_DAYS` | 0 disables cleanup; positive values delete expired v2 rows for this sensor |

Connection precedence: `AWS_RDS_CONNINFO`, `DATABASE_URL`, `POSTGRES_CONNINFO`, then libpq `PGHOST`/`PGPORT`/`PGDATABASE`/`PGUSER`/`PGPASSWORD`. Prefer PG variables for passwords containing spaces or quotes. `--no-db` overrides all connections. `--db-required` fails startup when PostgreSQL is unavailable; ordinary operation retains pending writes locally and reports degraded health.

## Statistics and recovery contract

JSON/API `schema_version=2`:

- `total_packets`: packets delivered by pcap, counted once.
- `total_bytes`: captured bytes; `wire_bytes`: pcap-reported original bytes.
- Protocol counters overlap by layer. TCP counts packets; stream-level HTTP/DNS/TLS counts complete recognized observations/messages. These are not interchangeable traffic totals.
- `analyzed`, queue/allocation drops, parser rejection observations, recording errors, detector/stream evictions, and alert saturation are reported separately.
- JSON totals are cumulative for the state directory. Database inserts are immutable interval deltas, with sensor/session/event identity and measured interval duration.

Only the persistence worker uses the PostgreSQL connection. JSON and pending journals are atomically replaced. Stable event IDs and primary keys make uncertain-commit retries idempotent. On restart, pending events are delivered before subsequent deltas; acknowledged totals are checkpointed before journals are removed.

A state directory is exclusively locked. Corrupt/incompatible files or a changed sensor identity fail initialization instead of silently resetting totals. Legacy JSON is preserved as `stats.json.legacy` and corrected counters start at zero. Different subsequent legacy snapshots receive unique archive filenames. Historical layer double-counting cannot be reconstructed; exclude legacy totals from new measurement comparisons.

Pending alert storage is bounded to 256 entries; overflow increments `alert_drops`. Journals preserve flushed events across database outages. Packets/counters and alerts not yet checkpointed can be lost on process termination or power failure. This is bounded-resource monitoring, not a lossless capture guarantee. Recording uses a separate 32 MiB queue; overflow or failed writes increments recording_errors. Filesystem stalls remain subject to operating-system I/O behavior.

## Protocol and detection scope

TCP analysis has 64 directional flows with 64 KiB data windows plus bounded presence/handshake buffers. It handles TCP segmentation, observed-SYN out-of-order delivery, retransmission deduplication, and TLS handshakes across records. Conflicting buffered overlaps retire the flow. Midstream capture cannot reconstruct data preceding the first observed segment. Flow state expires after 120 capture-time seconds.

HTTP requires complete headers and Content-Length-delimited bodies (or explicitly bodyless responses). Chunked/close-delimited response bodies and HTTP/2 are unsupported and counted accordingly. DNS-over-TCP supports multiple framed messages. DNS authorities/additionals are not fully decoded. TLS analysis does not decrypt application data or ECH. DHCPv6 provides message/relay classification rather than full option decoding.

Security rules are heuristics: distinct-target SYN bursts, long high-entropy DNS labels, recent ARP mapping conflicts scoped by network/VLAN, deduplicated DHCP transaction bursts, and unusually long SNI. Gratuitous ARP alone and large DNS messages alone do not imply attacks. Alert timestamps/windows use original capture time in UTC; replay speed does not change the event clock. Nonmonotonic timestamps reset applicable windows. Confidence remains heuristic; thresholds require calibration for the monitored network.

## HTTP API

Opt-in with `--api-port 8080 --api-token TOKEN`; default bind is `127.0.0.1`. Set `SNIFFER_API_CONTROL_TOKEN` to require a separate credential for filter updates. With a single token, that token grants both reading and control. For remote access, deploy an authenticated TLS proxy and keep the sniffer bound locally.

- `GET /health`: capture lifecycle/backlog and persistence health; liveness is distinct from capture readiness.
- `GET /stats`: cumulative schema-v2 snapshot.
- `GET /alerts?offset=0&limit=32`: recent in-memory alerts, oldest first; limits 1–32, offsets 0–128. Database retains durable history.
- `POST /filter` with `{"bpf":"tcp and (port 80 or port 443)"}`: capture-owned command, forbidden during replay.

HTTP/1.1 only, connection-close responses, maximum request buffer 8192 bytes/body 4096 bytes, up to 16 concurrent clients, two-second request/response deadlines, and 60 requests per client address per ten seconds. Chunked requests are rejected. Authorization is parsed only from headers. Tokens and BPF strings must fit configured fixed buffers; JSON escaped non-ASCII BPF characters are unsupported.

## Docker and Grafana

Copy `.env.example` to `.env` and fill credentials. Default services are PostgreSQL/Grafana; capture mode is explicit:

```sh
docker compose up -d postgres grafana
docker compose --profile replay run --build --rm replay
docker compose --profile live up --build -d sniffer
# Build/test the Linux container stage
docker build --target tests .
```

Bridge-mode live capture sees the sniffer container's namespace, not arbitrary host/LAN traffic. Native host capture is the portable option. On Linux, an explicitly configured host-network deployment can capture host interfaces, but its database endpoint must be reachable without Compose service DNS.

PostgreSQL and Grafana use loopback-published ports (5432, 3000). The datasource UID and environment substitution match the dashboard. Dashboard time range/sensor filters operate on v2 tables; protocol bytes are labeled overlapping. Password defaults are not supplied by Compose. Persistent volumes retain the database, Grafana, and live state.

## Migration and operations

`db_migration_add_dhcp.sql` is the canonical transactional v2 schema, embedded at build time. It creates `protocol_stats_v2`, `alerts_v2`, and `sniffer_schema` without modifying historical tables. It works beside timestamp-based and protocol-per-row legacy layouts. Apply it administratively for production, then grant the application the required insert/select privileges and provision a read-only Grafana role. The application validates a precreated v2 schema using reads and only runs migration DDL when that validation fails.

Database socket operations have two-second connection/query deadlines; system name resolution and filesystem operations remain subject to OS behavior. Local checkpoint failures cause nonzero shutdown status. Set a retention policy explicitly; defaults preserve history. Back up database/state before upgrades and use a new state directory if rolling back to the legacy executable.

See tests/README.md for fault-injection, fuzzing, and benchmark commands. MIT project license: LICENSE. Vendored jsmn has its own license in src/vendor/JSMN-LICENSE.

See [REMEDIATION.md](REMEDIATION.md) for the audit-to-change mapping, local verification record, rollout steps, and remaining verification limits.

Replay rows use original capture timestamps. Select the capture's time range in Grafana to view historical fixtures.
