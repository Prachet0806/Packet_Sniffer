# Remediation and verification record

Implementation reviewed and exercised locally on 2026-10-12. This record describes the resulting behavior, migration requirements, evidence, and remaining scope limits. Reproduction commands are in `tests/README.md`.

## Changes addressing the audit

| Audit concern | Implemented behavior | Principal evidence |
|---|---|---|
| TLS out-of-bounds reads and invalid protocol lengths | Validate record/handshake boundaries, cipher/compression lengths, IP/UDP lengths, DNS names/RDATA, and embedded ICMP headers | Regression, sanitizer integration, parser fuzzing |
| Invalid BPF cleanup and permissive startup failure | Initialize filter storage, free successful compilations, reject failed startup filters, preserve active filter after rejected commands | CLI integration and live control |
| Capture/filter races and unsafe shutdown | Capture owns pcap; API submits commands; signal handlers request shutdown; consumers join before resource destruction | Live control, API fixture, lifecycle inspection |
| API stalls and weak parsing/authentication | Nonblocking sockets, 16 clients, bounded buffers/deadlines, incremental HTTP parsing, partial writes, header-only authorization, separate control credential, rate limits, pagination | API integration and live control |
| Failures reported as success | Synchronous API bind/listen; nonzero input/filter/configuration/recording failures; required-database startup policy | Missing-input, invalid-filter/configuration, occupied-port tests |
| Capture totals count layers repeatedly | Capture totals increment once; protocol observations explicitly overlap; captured and wire bytes are distinct | Exact comparison against every corpus PCAP record |
| Flush resets lose increments | Immutable delta/target snapshots, cumulative totals and acknowledged watermarks; shared field list includes all protocol byte counters | Delayed-insert/concurrent-update database test, JSON round trip |
| Duplicate delivery and incomplete recovery | Atomic checkpoints, stable event IDs, primary-key deduplication, journals, serialized persistence, sensor/version/watermark validation, synchronized event numbering | Outage/restart and damaged-journal tests |
| Incorrect legacy migrations and absent alert persistence | Separate v2 tables preserve history; archive legacy JSON and start corrected totals at zero; bounded durable alert queue | Legacy preservation and durable-alert tests |
| Partial schema validation and runtime DDL requirements | Validate every persisted counter and metadata column; pre-migrated schema works with select/insert privileges | Restricted-role and incomplete-schema tests |
| Wrong SLL2 and guessed link formats | Genuine 20-byte SLL2, exact NULL/LOOP/SLL/raw dispatch, unsupported outcomes; preserve old invalid fixture separately | Corpus assertions |
| Packet-only TCP application parsing | Bounded sequence windows, gaps/retransmissions, HTTP/DNS framing, TLS assembly, new-SYN tuple reuse reset | Out-of-order, duplicate-payload, repeated-SYN and tuple-reuse regressions |
| Noisy heuristics and replay-dependent clocks | Capture-time windows, distinct SYN targets, network-scoped ARP, DNS-label entropy, DHCP transaction deduplication, heuristic confidence | Benign/anomaly and retransmission regressions |
| Blocking logging/recording and unbounded resource growth | Separate bounded queues and detector/stream state; queue/allocation/recording/alert/eviction counters | Replay benchmark, live recording, code inspection |
| Docker production/test mismatch | Explicit builder/runtime and test stages; optional test/PostgreSQL builds | Docker test stage and PostgreSQL-free CTest |
| Compose networking and Grafana mismatch | Shared network, explicit live/replay profiles, loopback ports, required passwords, persistent volumes, matching datasource UID/environment, v2 time/sensor queries | Isolated Compose replay and eight dashboard query checks |
| Thin tests and inconsistent tooling | Release-active assertions, isolated integration, database fault injection, sanitizers/fuzzing, DLL architecture validation, CI coverage | Windows/Linux/container runs below |
| Missing operational contracts and licensing | Configuration ranges/precedence, recovery guarantees, protocol scope, migration/rollback, AWS guidance, project/vendor licenses | README, AWS guides, license files |

## Verification performed

- Windows x64 MSVC 19.44 Release build and CTest passed with Npcap runtime and PostgreSQL 17 client libraries.
- Ubuntu 22.04 under WSL: Clang 14 AddressSanitizer/UndefinedBehaviorSanitizer build and CTest passed.
- Ubuntu 22.04 under WSL: GCC 11 Release build with `SNIFFER_POSTGRES=OFF` and CTest passed.
- PostgreSQL 17 disposable database: 15 checks passed, including delayed concurrent inserts, successive sessions, durable alerts, outage/recovery, restricted privileges, incomplete schema, and damaged journals. Legacy rows remained intact.
- Debian Bookworm Docker production/test stages built; container CTest passed.
- Isolated Compose PostgreSQL 15/Grafana 11.3.0: replay persisted, datasource health passed, dashboard provisioned, and all eight panel queries executed successfully.
- Privileged Linux loopback: seven control/recording checks passed, including credential separation, valid/invalid filter changes, synthetic UDP capture, recorded output, and SIGTERM shutdown.
- A bounded parser fuzz run completed 297,716 executions in 21 seconds with no sanitizer findings; an earlier run completed 457,461. These runs are sampling evidence, not exhaustive proof.
- Replay benchmark: 100,000 repeated HTTP records in approximately 0.916 seconds (109,177 packets/second), zero analysis queue drops, and one HTTP observation due to retransmission deduplication. This measures that fixture and machine; it is not a live capacity guarantee.
- `git diff --check` passed. Existing `.env`, root `stats.json`, `pgdata`, and preexisting `stderr.txt` were preserved.

## Migration and rollout

1. Back up state and database. Build and run the isolated tests before deployment.
2. Apply `db_migration_add_dhcp.sql` administratively; grant the application select/insert on v2 tables and select on the schema version table. Use a read-only Grafana account. Retention additionally needs delete privileges.
3. Choose one persistent state directory and sensor identity per process. The directory is exclusively locked. Legacy snapshots are archived; corrected counters start at zero.
4. Update consumers to schema version 2: JSON/API totals are cumulative; database rows are interval deltas; protocol counters overlap. Select original capture dates for historical replay dashboards.
5. Start with representative traffic and inspect health, drop/rejection counters, database deltas, and alert quality. Set retention and calibrate thresholds.
6. To roll back, stop the new executable and run the previous version with a different state directory. Historical tables are preserved; the previous dashboard does not consume v2 rows.

## Remaining capability and verification limits

- No IP fragment reassembly, HTTP chunked/close-delimited body decoding, or HTTP/2. DNS authority/additional sections and DHCPv6 options are not fully decoded. TLS application data/ECH remain encrypted. Unsupported/incomplete cases are surfaced.
- Stream state is bounded to 64 directional flows and 64 KiB windows. Missing segments, midstream capture, expiry, conflicting buffered overlaps, and capacity eviction limit reconstruction. This is not a full network stack.
- Detector output remains heuristic. Representative labeled network data and operator calibration are required to quantify false positives/negatives.
- Durability covers checkpointed events. Sudden termination can lose uncheckpointed observations. Saturated alert/recording queues can drop data; counters expose that loss. Application counters do not measure kernel capture loss.
- Socket operations have deadlines; OS name resolution and filesystem stalls can still delay operations. Slow-output/filesystem failure behavior was not exhaustively fault-injected on every platform.
- Native Windows live Npcap/console shutdown, ARM64/x86 combinations, macOS, remote RDS certificate negotiation, sustained live overload, and power-loss recovery were not verified here.
- Grafana provisioning and SQL were verified through its API; browser rendering/accessibility were not visually audited.
- CI definitions were updated, but hosted GitHub Actions have not run for this uncommitted change. Reported builds/tests ran locally.

Temporary verification database/container services are stopped after the checks. Generated artifacts remain under ignored `build/`; no commit or production deployment was made.
