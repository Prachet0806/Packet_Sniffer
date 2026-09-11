# Parser smoke tests
# Requires: gcc + Npcap SDK (Windows) or libpcap-dev (Linux).
# Run from repo root:
#   gcc -Isrc -IC:/npcap-sdk/Include tests/smoke_parsers.c src/ethernet.c src/ip.c src/tcp.c src/udp.c src/dns.c src/arp.c src/icmp.c src/http.c src/https.c src/stats.c src/db.c -o /tmp/smoke -L"C:/npcap-sdk/Lib/x64" -lwpcap -lPacket -lws2_32 -liphlpapi && /tmp/smoke
# Must print SMOKE_OK and exit 0. Any crash/hang = failure.
# Cases: truncated ethernet, VLAN, non-first fragment skip, DNS compression
# loop (must return, not hang), valid DNS query, HTTP with embedded NUL
# (must not OOB-read), TLS multi-record + truncated, TCP->HTTP dispatch.
