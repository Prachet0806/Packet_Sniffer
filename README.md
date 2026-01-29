# Packet Sniffer + Protocol Analyzer

A C-based packet sniffer that captures live traffic, parses common protocols, and periodically flushes stats to JSON and PostgreSQL (local Docker by default, AWS RDS when configured).

## What it does
- Capture thread (pcap) + analysis thread with a thread-safe queue.
- Protocol parsing: Ethernet, ARP, IPv4/IPv6, TCP, UDP, ICMP, DNS, HTTP, HTTPS.
- Stats tracking with periodic flush to `stats.json` and PostgreSQL via libpq.
- Graceful Ctrl+C handling with final flush attempts.

## Architecture
```
┌─────────────────────────────────────┐
│              main.c                 │ ← Entry point
│              sniffer.c/.h           │ ← Core capture engine
│              analyzer.c/.h          │ ← Analysis coordinator
├─────────────────────────────────────┤
│           ethernet.c/.h             │ ← Data Link Layer
│           arp.c/.h                  │
├─────────────────────────────────────┤
│              ip.c/.h                │ ← Network Layer (IPv4/IPv6)
├─────────────────────────────────────┤
│         tcp.c/.h  │  udp.c/.h       │ ← Transport Layer
│         icmp.c/.h                   │
├─────────────────────────────────────┤
│              dns.c/.h               │ ← Application Layer
│              dhcp.c/.h              │
│        http.c/.h  │  https.c/.h     │
└─────────────────────────────────────┘
```

## Build
### Windows (example)
```bash
gcc src/*.c -o build/sniffer.exe -lws2_32 -liphlpapi -lpcap -lpq
```
Requires WinPcap/libpcap dev headers, Winsock2, and libpq (PostgreSQL client library).

### Linux/macOS
```bash
gcc src/*.c -o sniffer -lpcap -lpq -lpthread
```

**Note:** Make sure all `.c` files in `src/` are included.

## Configure
- Copy `env.example` to `.env` and set `AWS_RDS_CONNINFO`.
- If not set, it falls back to local Docker:
  `host=localhost port=5432 dbname=snifferdb user=sniffer password=snifferpass sslmode=disable`
- `.env` is auto-loaded on startup (best-effort), then normal environment variables are read.

### AWS RDS connection example
```
AWS_RDS_CONNINFO=host=<instance>.us-east-1.rds.amazonaws.com port=5432 dbname=snifferdb user=sniffer_admin password=<password> sslmode=require connect_timeout=5
```
Ensure your security group allows your client IP, and the user has CONNECT/USAGE/INSERT permissions. See `AWS_RDS_QUICK_START.md` for detailed setup instructions.

### Table schema expectation
`protocol_stats` (optionally in `telemetry` schema): bigint counters, `timestamp` default now. Set `search_path` or qualify the table if using a non-public schema.

## Run
```bash
./build/sniffer.exe   # choose an interface when prompted
```
The batch thread flushes to PostgreSQL and `stats.json` every ~15 seconds. On failure, it retries with backoff and reconnects on the next flush.

## Recent Improvements (Jan 2026)
- ✅ **Queue size limit** - Bounded memory usage (max 10,000 packets)
- ✅ **64-bit counters** - No overflow on long-running captures
- ✅ **Logging levels** - Reduced verbosity for better performance (~100x faster)
- ✅ **Capture statistics** - Track drop rates, queue depth, and performance
- ✅ **Safe signal handling** - POSIX-compliant Ctrl+C handler
- ✅ **Event-based thread shutdown** - Clean termination without race conditions
- ✅ **Error tracking** - Visibility into allocation failures and drops

### Threading Model
- **Capture Thread**: Continuously captures packets using pcap_dispatch()
- **Analysis Thread**: Processes queued packets through protocol stack
- **Thread-safe Queue**: Uses Windows Critical Sections and Condition Variables

### Memory Management
- Dynamic packet buffer allocation
- Automatic cleanup after analysis
- Efficient memory usage with proper deallocation

### Performance Features
- Zero-copy packet queuing
- Lock-free data structures where possible
- Optimized protocol parsing algorithms

## File Structure
```
Packet_Sniffer/
├── src/
│   ├── main.c              # Application entry point
│   ├── sniffer.c/.h        # Core packet capture engine
│   ├── analyzer.c/.h       # Packet analysis coordinator
│   ├── ethernet.c/.h       # Ethernet frame parsing
│   ├── ip.c/.h             # IPv4/IPv6 packet parsing
│   ├── tcp.c/.h            # TCP segment parsing
│   ├── udp.c/.h            # UDP datagram parsing
│   ├── icmp.c/.h           # ICMP message parsing
│   ├── arp.c/.h            # ARP packet parsing
│   ├── dns.c/.h            # DNS query/response parsing
│   ├── dhcp.c/.h           # DHCP message parsing
│   ├── http.c/.h           # HTTP parsing
|   ├── https.c/.h           # HTTPS parsing
│   └── stats.c/.h          # stats counting and flushing to DB
├── build/
│   └── sniffer.exe        # Compiled executable
└── README.md
```
## Troubleshooting (PostgreSQL)
- Connection failures print `PQerrorMessage` from retry attempts.
- Auth errors: verify username, password, DB name, security group rules, and `sslmode=require`.

### Quick Connection Test
```bash
psql "host=<instance>.region.rds.amazonaws.com port=5432 dbname=snifferdb user=sniffer_admin password=<password> sslmode=require" -c "select 1;"
```

## Protocol Support
- Ethernet, ARP
- IPv4 / IPv6
- TCP, UDP, ICMP
- DNS, DHCP
- HTTP, HTTPS

## Development

### Adding New Protocols
1. Create protocol header file (`protocol.h`)
2. Implement parser function (`protocol.c`)
3. Add protocol detection in appropriate layer
4. Update includes and function calls


## Future Enhancements
- [x] DHCP protocol parsing (✅ Implemented Jan 2026)
- [ ] Packet filtering capabilities
- [ ] PCAP file export
- [ ] GUI interface
- [ ] REST API for remote access

