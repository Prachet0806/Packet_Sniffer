# Packet Sniffer + Protocol Analyzer

A high-performance, multi-threaded network packet sniffer and protocol analyzer built in C. This tool captures network packets in real-time and provides detailed analysis of various network protocols.

## Features

### Core Capabilities
- **Multi-threaded Architecture**: Separate capture and analysis threads for optimal performance
- **Thread-safe Queue**: Efficient packet buffering between capture and analysis
- **Real-time Analysis**: Live packet dissection and display
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
- **ICMPv4**: Message types (Echo, Unreachable, Redirect, etc.)
- **ICMPv6**: IPv6 control messages (Echo, Neighbor Discovery, etc.)

#### Application Layer
- **DNS**: Complete DNS query/response analysis
  - A, AAAA, CNAME, MX, NS, PTR, TXT records
  - Name compression support
  - Query/Response flag analysis

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
└─────────────────────────────────────┘
```
## Building

### Prerequisites
- GCC compiler
- WinPcap/libpcap development libraries
- Windows Sockets (Winsock2)

### Compilation
```bash
gcc src/*.c -o build/sniffer.exe -lws2_32 -liphlpapi -lpcap
```

### Linux/macOS
```bash
gcc src/*.c -o sniffer -lpcap
```

## Usage

1. **Run the application**:
   ```bash
   ./build/sniffer.exe
   ```

2. **Select network interface**:
   - The program lists all available network interfaces
   - Choose the interface number to monitor

3. **Monitor traffic**:
   - Packets are captured and analyzed in real-time
   - Detailed protocol information is displayed

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
```

## Technical Details

### Threading Model
- **Capture Thread**: Continuously captures packets using pcap_loop()
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
│   ├── ip.c/.h            # IPv4/IPv6 packet parsing
│   ├── tcp.c/.h           # TCP segment parsing
│   ├── udp.c/.h           # UDP datagram parsing
│   ├── icmp.c/.h          # ICMP message parsing
│   ├── arp.c/.h           # ARP packet parsing
│   └── dns.c/.h           # DNS query/response parsing
├── build/
│   └── sniffer.exe        # Compiled executable
└── README.md              # This file
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
- **Operation Types**: Request, Reply, RARP Request/Reply
- **Address Resolution**: IP-to-MAC mapping display
- **Broadcast Detection**: Identifies broadcast ARP requests

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

## License

This project is open source and available under the MIT License.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## Future Enhancements

- [ ] HTTP/HTTPS protocol support
- [ ] DHCP protocol parsing
- [ ] VLAN (802.1Q) support
- [ ] Packet filtering capabilities
- [ ] PCAP file export
- [ ] Real-time statistics
- [ ] GUI interface
- [ ] REST API for remote access
