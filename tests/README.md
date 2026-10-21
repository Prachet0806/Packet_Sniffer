# Verification

CMake/CTest registers an isolated integration suite. It creates temporary state directories, strips inherited application configuration, and requires no capture privileges or external database:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

It checks capture totals for every PCAP, genuine SLL2 and the preserved invalid fixture, JSON round trips/uint64 boundaries, TLS truncation, malformed protocol lengths, distinct-target heuristics, network-scoped ARP, TCP out-of-order/retransmission behavior, quiet/CLI precedence, HTTP fragmentation/authentication/header parsing, stalled clients, occupied API ports, and shutdown.

PostgreSQL integration must use a disposable database. The script creates test tables/functions and a slow-insert trigger:

```sh
python tests/postgres_integration.py build/sniffer build/stats_stress /usr/bin/psql 'host=127.0.0.1 port=55432 dbname=sniffer_test user=sniffer' .
```

Windows binaries are under build/Release. This verifies legacy schema preservation, restricted database privileges, rejection of incomplete schemas and damaged journals, concurrent counter updates during delayed inserts, cumulative watermarks, alert durability, repeated sessions, database outage journals, and recovery. Do not target a production database.

Pass the executable path `/usr/bin/psql` directly on Debian/Ubuntu. It is a launcher symlink whose behavior depends on the name used to invoke it; the integration runner preserves that path.

Clang sanitizer build: use `-DSNIFFER_SANITIZERS=ON`. Fuzzing build:

```sh
cmake -S . -B build-fuzz -DCMAKE_C_COMPILER=clang -DBUILD_TESTING=OFF -DSNIFFER_FUZZ=ON
cmake --build build-fuzz
SNIFFER_STATE_DIR=build-fuzz/state ./build-fuzz/fuzz_parsers -max_total_time=30
```

Replay benchmark (includes startup/checkpoint/shutdown):

```sh
python tests/benchmark.py build/sniffer 100000
```

Repeated sequence numbers measure retransmission deduplication and replay throughput; they do not demonstrate live wire-rate capacity. Live capture, platform-specific console events, and container/Grafana rendering require their corresponding environments.

Privileged Linux loopback control/recording test (captures only synthetic loopback traffic):

```sh
sudo python3 tests/live_control.py build/sniffer
```

For isolated Docker/Grafana checks, start Compose with a distinct project name and override its published ports (the checker defaults to Grafana port 57300):

```sh
python tests/docker_integration.py http://127.0.0.1:57300 TEST-GRAFANA-PASSWORD
```

The checker validates datasource health, provisioned dashboard identity, replay persistence, and all panel SQL queries. Replay fixtures retain their original timestamps; select the historical capture range when viewing them.
