# Packet Sniffer + Protocol Analyzer

A high-performance, multi-threaded network packet sniffer and protocol analyzer built in C. This tool captures network packets in real-time and provides detailed analysis of various network protocols.

## Features

### Core Capabilities
- **Multi-threaded Architecture**: Separate capture and analysis threads for optimal performance
- **Thread-safe Queue**: Efficient packet buffering between capture and analysis
- **Real-time Analysis**: Live packet dissection and display
- **Statistics Collection**: Protocol-wise packet and byte counting with thread-safe aggregation
- **Database Integration**: PostgreSQL storage for persistent statistics
- **JSON Export/Import**: Statistics persistence in JSON format
- **Docker Support**: Containerized deployment with Docker and Docker Compose
- **Cross-platform Ready**: Uses libpcap (Windows/Linux/macOS compatible)

### Supported Protocols

#### Data Link Layer
- **Ethernet**: MAC address extraction, EtherType identification
- **ARP**: Address Resolution Protocol (Request/Reply/RARP)

#### Network Layer
- **IPv4**: Complete header parsing, fragmentation support
- **IPv6**: Full header parsing with extension header support
  - Hop-by-Hop Options
  - Destination Options
  - Routing Headers
  - Fragment Headers

#### Transport Layer
- **TCP**: Port analysis, sequence numbers, flags, window size
- **UDP**: Port analysis, length validation
- **ICMPv4**: Message types (Echo, Unreachable, Redirect, etc.) + embedded
  offending-packet attribution for error messages
- **ICMPv6**: IPv6 control messages (Echo, Neighbor Discovery, etc.) + embedded
  packet attribution for error types 1-4

#### Application Layer
- **DNS**: Complete DNS query/response analysis
  - A, AAAA, CNAME, MX, NS, PTR, TXT records
  - Name compression support
  - Query/Response flag analysis
- **HTTP**: HTTP request/response parsing
  - Request method and URI extraction
  - Host header detection
  - Response status line parsing
- **HTTPS/TLS**: TLS protocol analysis
  - TLS record type identification
  - TLS version detection (SSL 3.0–TLS 1.2; 1.3 uses legacy `0x0303` on the wire)
  - ClientHello SNI extraction
  - Handshake and application data tracking
- **DHCP**: DISCOVER/OFFER/REQUEST/ACK parsing (UDP ports 67/68) + minimal
  DHCPv6 classifier (ports 546/547)
  - Magic-cookie validation, message-type/lease/hostname options
  - See `db_migration_add_dhcp.sql`, `AWS_RDS_QUICK_START.md`

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
│         dns.c/.h  │  http.c/.h      │ ← Application Layer
│   https.c/.h │ dhcp.c/.h │ logger.c/.h │
├─────────────────────────────────────┤
│         stats.c/.h  │  db.c/.h      │ ← Data Management
└─────────────────────────────────────┘
```

## Building

### Prerequisites
- CMake 3.16+, C11 compiler (MSVC / GCC / Clang)
- Npcap SDK (Windows, set `NPCAP_SDK`) or libpcap-dev (Linux)
- PostgreSQL client (optional; set `POSTGRES_ROOT` on Windows). Build works without it (JSON-only mode).
- Docker and Docker Compose - optional, for containerized deployment

### Compilation (all platforms, recommended)
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
# binary: build/sniffer  (Windows: build/Release/sniffer.exe)
```

Windows notes: open a VS Developer Prompt so `cl` is on PATH, or use
`"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"`.
MSVC + `libpq.lib` is required for PostgreSQL support with `cl`; MinGW builds
default to JSON-only unless a MinGW-compatible libpq is provided.

### Docker Deployment
```bash
# Copy secrets template first
copy .env.example .env   # Windows / cp .env.example .env on Linux
# Live capture (needs NET_RAW/NET_ADMIN) + Postgres + provisioned Grafana:
docker compose up --build -d
# Deterministic demo without privileges (replay profile):
docker compose --profile replay up --build replay
# Grafana :3000 (admin/admin) uses provisioned Postgres datasource, no manual setup.
# sniffer service uses bridge networking (host=postgres); network_mode:host is
# intentionally NOT used because it breaks compose DNS for host=postgres.
```

## Quickstart (replay, no admin) vs Live vs Docker vs RDS
- Replay (deterministic, no root): `sniffer --read tests/pcaps/eth-tcp-http.pcap --no-db --quiet`
- Live: `sniffer --iface 1 --filter "tcp port 80" --verbose` (admin/root or NET_RAW)
- Docker: see above; `replay` profile feeds Postgres/Grafana from `/pcaps`.
- RDS: set `AWS_RDS_CONNINFO` (preferred) or `DATABASE_URL`; schema canonical key is
  `protocol_stats.interval_start` (interval deltas in Postgres, cumulative in `stats.json`;
  dashboards must `SUM()` over window, not read last row as gauge).
- API (opt-in): `sniffer --api-port 8080 --api-token $TOKEN` then
  `curl -H "Authorization: Bearer $TOKEN" localhost:8080/health|/stats|/alerts`.
  Default bind `127.0.0.1` (`--api-bind 0.0.0.0` for Docker). `POST /filter {"bpf":"tcp port 80"}`
  is live-only (rejected in `--read` mode). Unauth -> 401, burst -> 429.
- Alerts (rule-based, no ML): SYN-scan, DNS-tunnel heuristics, ARP-spoof (gratuitous/flap),
  DHCP-starvation (DISCOVER burst), TLS SNI length. Sink: stderr `[ALERT]` + `GET /alerts`
  + `alerts(time,type,src,dst,detail)` table + Grafana panel. Blind spots: no TCP reassembly,
  non-first frag skipped, IPv6 frag/ESP/AH stop, VLAN>2 truncated, port-heuristic evasion,
  DNS auth/addl skipped, only first ClientHello SNI (ECH/TLS1.3 hidden).

## Usage

1. **Run the application** (capture needs admin/root or `NET_RAW`/`NET_ADMIN`):
   ```bash
   ./build/sniffer --help
   ./build/sniffer --iface 1 --filter "tcp port 80" --verbose
   ./build/sniffer --iface eth0 --no-promisc --snaplen 4096 --write out.pcap --quiet
   # Env alternatives: SNIFFER_IFACE, SNIFFER_FILTER, SNIFFER_VERBOSE=1,
   #   SNIFFER_SNAPLEN, SNIFFER_PROMISC=0, SNIFFER_TIMEOUT_MS, SNIFFER_WRITE,
   #   DATABASE_URL="host=localhost port=5432 dbname=snifferdb user=sniffer password=...",
   #   AWS_RDS_CONNINFO (preferred for RDS), STATS_FLUSH_MS=60000, LOG_LEVEL=0-3,
   #   --no-db for JSON-only
   ```
   Kernel drop counters (`pcap_stats`) and queue drops print on exit.

2. **Select network interface**:
   - Without `--iface`/`SNIFFER_IFACE` the program lists interfaces and prompts.
   - In Docker / non-interactive shells you must pass `--iface` (index or name
     substring) or set `SNIFFER_IFACE`, otherwise it exits instead of hanging.

3. **Monitor traffic**:
   - Packets are captured and analyzed in real-time
   - Detailed protocol information is displayed
   - Statistics are collected and can be exported to JSON or PostgreSQL

4. **View statistics**:
   - Statistics are automatically saved to `stats.json` (cumulative snapshot,
     git-ignored) every flush interval
   - PostgreSQL inserts are per-interval (counters reset after a successful
     insert) — see `STATS_FLUSH_MS`, `db_ensure_schema()`, and
     `db_migration_add_dhcp.sql` for older databases
   - Configure PostgreSQL connection for database storage
   - Use Grafana (via Docker Compose) for visualization

## Sample Output

```
=== Packet Sniffer + Protocol Analyzer ===

=== Available Devices ===
1. \Device\NPF_{GUID} - Ethernet adapter (MAC: 00:11:22:33:44:55)

Enter device number to capture: 1
Listening on \Device\NPF_{GUID}...

[+] Packet captured: length 74 bytes

[Ethernet] Src MAC 00:11:22:33:44:55, Dst MAC FF:FF:FF:FF:FF:FF, Type 0x0806
ARP: ARP Request
     Sender: 192.168.1.100 (00:11:22:33:44:55)
     Target: 192.168.1.1 (Broadcast)
     Hardware Type: Ethernet (0x0001)
     Protocol Type: IPv4 (0x0800)

[+] Packet captured: length 98 bytes

[Ethernet] Src MAC 00:11:22:33:44:55, Dst MAC 08:00:27:12:34:56, Type 0x0800
IPv4: 192.168.1.100 -> 8.8.8.8, TTL=64, Proto=17, Len=78
UDP: 192.168.1.100:54321 -> 8.8.8.8:53, Len=58
DNS: Query (ID=0x1234)
     Flags: RD 
     Questions: 1, Answers: 0, Authorities: 0, Additional: 0
     Question: google.com (Type=1, Class=1)

[+] Packet captured: length 542 bytes

[Ethernet] Src MAC 00:11:22:33:44:55, Dst MAC 08:00:27:12:34:56, Type 0x0800
IPv4: 192.168.1.100 -> 93.184.216.34, TTL=64, Proto=6, Len=528
TCP: 192.168.1.100:54321 -> 93.184.216.34:80, Seq=1234567890 Ack=987654321, Win=65535 [ACK PSH]
[HTTP] 192.168.1.100:54321 -> 93.184.216.34:80 | GET /index.html HTTP/1.1
[HTTP]   Host: example.com

[+] Packet captured: length 128 bytes

[Ethernet] Src MAC 00:11:22:33:44:55, Dst MAC 08:00:27:12:34:56, Type 0x0800
IPv4: 192.168.1.100 -> 172.217.164.110, TTL=64, Proto=6, Len=114
TCP: 192.168.1.100:54322 -> 172.217.164.110:443, Seq=2345678901 Ack=0, Win=65535 [SYN]
HTTPS: 192.168.1.100:54322 -> 172.217.164.110:443, TLS Record: Handshake, Version=TLS 1.2-or-1.3-wire, Length=89
HTTPS:   SNI=example.com
```

## Technical Details

### Threading Model
- **Capture Thread**: Continuously captures packets using pcap_loop()
- **Analysis Thread**: Processes queued packets through protocol stack
- **Thread-safe Queue**: Critical Sections / pthread mutexes + condition variables
- **Thread-safe Logging**: All log output serialized through `logger.c`; packet-derived
  strings are sanitized (non-printables → `.`) against terminal-escape injection

### Memory Management
- Dynamic packet buffer allocation
- Automatic cleanup after analysis
- Efficient memory usage with proper deallocation

### Performance Features
- Zero-copy packet queuing
- Lock-free data structures where possible
- Optimized protocol parsing algorithms
- Batch statistics updates for reduced database overhead

### Statistics & Data Management
- **Thread-safe Statistics**: Protocol-wise packet and byte counting
- **JSON Persistence**: Statistics export/import in JSON format
- **PostgreSQL Integration**: Persistent storage in PostgreSQL database
- **Batch Processing**: Periodic batch updates to reduce database load
- **Grafana Integration**: Ready for visualization with Grafana (via Docker Compose)

## File Structure

```
Packet_Sniffer/
├── src/
│   ├── main.c              # Application entry point
│   ├── sniffer.c/.h        # Core packet capture engine
│   ├── analyzer.c/.h       # Packet analysis coordinator
│   ├── ethernet.c/.h       # Ethernet frame parsing
│   ├── ip.c/.h            # IPv4/IPv6 packet parsing
│   ├── tcp.c/.h           # TCP segment parsing
│   ├── udp.c/.h           # UDP datagram parsing
│   ├── icmp.c/.h          # ICMP message parsing
│   ├── arp.c/.h           # ARP packet parsing
│   ├── dns.c/.h           # DNS query/response parsing
│   ├── dhcp.c/.h          # DHCP message parsing (ports 67/68)
│   ├── logger.c/.h        # Log-level gated logging
│   ├── http.c/.h          # HTTP protocol parsing
│   ├── https.c/.h         # HTTPS/TLS protocol parsing
│   ├── stats.c/.h         # Statistics collection and management
│   └── db.c/.h            # PostgreSQL database integration
├── db_migration_add_dhcp.sql  # DHCP columns migration
├── AWS_RDS_QUICK_START.md / AWS_QUICK_REFERENCE.md  # RDS docs
├── build/
│   ├── sniffer.exe        # Compiled executable
│   └── stats.json         # Statistics export file
├── pgdata/                # PostgreSQL data volume (Docker)
├── Dockerfile             # Docker container definition
├── docker-compose.yaml    # Docker Compose configuration
├── .gitignore            # Git ignore rules
└── README.md             # This file
```

## Protocol Support Details

### IPv6 Extension Headers
- **Hop-by-Hop Options**: Router-examined options
- **Destination Options**: Destination-specific configuration
- **Routing Headers**: Source routing with segment tracking
- **Fragment Headers**: IPv6 fragmentation information

### DNS Features
- **Record Types**: A, AAAA, CNAME, MX, NS, PTR, TXT
- **Name Compression**: Handles DNS pointer compression
- **Flag Analysis**: QR, AA, TC, RD, RA, AD, CD flags
- **Response Codes**: Complete error code interpretation

### ARP Support
- **Operation Types**: Request, Reply (RARP shares the ARP format on EtherType `0x8035`)
- **Address Resolution**: IP-to-MAC mapping display
- **Broadcast Detection**: Identifies broadcast ARP requests

### HTTP Features
- **Request Parsing**: HTTP method, URI, and version extraction
- **Header Analysis**: Host header detection and display
- **Response Parsing**: HTTP status line analysis
- **Case-insensitive Matching**: Robust header field detection

### HTTPS/TLS Features
- **TLS Record Parsing**: Content type identification (Handshake, ApplicationData, Alert, etc.)
- **Version Detection**: SSL 3.0–TLS 1.2; TLS 1.3 uses legacy `0x0303` on the wire
  (true version is in the `supported_versions` extension), so it is reported as
  `TLS 1.2-or-1.3-wire`.
- **Record Length Analysis**: TLS record size tracking, truncated-record detection
- **Future Extension**: SNI parsing

### Statistics System
- **Protocol Counters**: Per-protocol packet and byte counts
- **Thread-safe Updates**: Concurrent statistics updates with critical sections
- **Batch Processing**: Periodic database updates for performance
- **JSON Export**: Human-readable statistics in JSON format
- **Database Integration**: PostgreSQL storage for historical analysis
- **Auto-save**: Automatic statistics persistence on shutdown

## Development

### Adding New Protocols
1. Create protocol header file (`protocol.h`)
2. Implement parser function (`protocol.c`)
3. Add protocol detection in appropriate layer
4. Update includes and function calls

### Code Style
- Minimal, functional comments
- Consistent naming conventions
- Proper error handling and validation
- Thread-safe implementations


## Configuration

### Statistics Configuration
Statistics are automatically collected and can be configured via the `stats_init()` function:
- **JSON file**: `stats.json` (auto-generated in build directory)
- **PostgreSQL**: Configure connection string in `stats_init()`
  - Format: `"host=localhost port=5432 dbname=snifferdb user=sniffer password=snifferpass"`
- **Batch interval**: Configurable batch update frequency (default: periodic updates)

### Docker Configuration
The `docker-compose.yaml` includes:
- **PostgreSQL**: Database for statistics storage (port 5432)
  - User: `sniffer`
  - Password: `snifferpass`
  - Database: `snifferdb`
- **Grafana**: Visualization dashboard (port 3000)
  - Default credentials: `admin/admin`
  - Pre-configured to connect to PostgreSQL
  - Access at: `http://localhost:3000`

### Database Setup
1. **Using Docker Compose** (Recommended):
   ```bash
   docker-compose up -d postgres
   ```
   This automatically creates the database and required tables.

2. **Manual PostgreSQL Setup**:
   ```sql
   CREATE DATABASE snifferdb;
   CREATE USER sniffer WITH PASSWORD 'snifferpass';
   GRANT ALL PRIVILEGES ON DATABASE snifferdb TO sniffer;
   ```

### Database Schema
PostgreSQL table structure (auto-created by the application):
```sql
CREATE TABLE IF NOT EXISTS protocol_stats (
    id SERIAL PRIMARY KEY,
    protocol VARCHAR(32) UNIQUE NOT NULL,
    packet_count BIGINT DEFAULT 0,
    byte_count BIGINT DEFAULT 0,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Future Enhancements

- [x] HTTP/HTTPS protocol support
- [x] DHCP protocol parsing (DISCOVER/OFFER/REQUEST/ACK, ports 67/68)
- [x] Statistics collection system
- [x] Database integration (incl. `db_migration_add_dhcp.sql`, AWS RDS docs)
- [x] Docker containerization
- [x] VLAN (802.1Q) support
- [x] Packet filtering capabilities (`--filter` BPF)
- [x] PCAP file export (`--write out.pcap`)
- [ ] GUI interface
- [ ] REST API for remote access
- [ ] Real-time Grafana dashboards
- [ ] Machine learning anomaly detection

## License

This project is open source and available under the MIT License.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.
