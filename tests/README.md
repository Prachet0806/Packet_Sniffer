# Parser smoke tests + replay corpus
Requires: CMake + Npcap SDK (Windows) or libpcap-dev (Linux).
Run from repo root:
  cmake -S . -B build && cmake --build build --config Release && ctest --test-dir build --output-on-failure
Smoke binary also runs standalone:
  ./build/Release/smoke ./smoke-stats.json   (Windows)
  ./build/smoke ./smoke-stats.json           (Linux)
Must print SMOKE_OK and exit 0. Any crash/hang = failure.
Cases: truncated ethernet, VLAN, non-first fragment skip, DNS compression
loop (must return, not hang), valid DNS query, HTTP with embedded NUL
(must not OOB-read), TLS multi-record + truncated, TCP->HTTP dispatch,
DHCPv6 SOLICIT, DHCPv4 bad-op reject, ClientHello SNI, ICMPv4 embedded flow.
Replay corpus tests/pcaps/ (<100KB each): eth-tcp-http, dns, arp, vlan (2 tags),
loop-null, linux-sll (113), sll2 (114), raw-ip, truncated-snaplen, empty.
Each exercises one analyzer DLT branch + queue clamp path:
  sniffer --read tests/pcaps/eth-tcp-http.pcap --no-db --quiet
API fixture tests/api_alive.c: builds to build/Release/api_alive.exe,
starts the API for ~8s for manual curl checks (see README Quickstart).
