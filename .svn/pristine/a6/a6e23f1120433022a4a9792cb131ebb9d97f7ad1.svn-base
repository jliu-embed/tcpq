# tcpq - TCP Packet Analyzer

A Qt-based network packet analyzer inspired by tcpdump.

## Features

- Packet capture using libpcap
- Real-time packet display  
- **IP and Port filtering**
- TCP/UDP/ICMP protocol analysis
- Filter expression support

## Filtering Syntax

```bash
# Filter by source IP
tcpq -f "src 192.168.1.1"

# Filter by destination IP
tcpq -f "dst 10.0.0.1"

# Filter by host (either src or dst)
tcpq -f "host 192.168.1.1"

# Filter by source port
tcpq -f "src port 80"

# Filter by destination port
tcpq -f "dst port 443"

# Filter by port (either src or dst)
tcpq -f "port 8080"

# Filter by protocol
tcpq -f "tcp"
tcpq -f "udp"
tcpq -f "icmp"

# Combine filters
tcpq -f "src 192.168.1.1 and dst port 80"
```

## Requirements

- Qt5
- libpcap-dev

## Building

```bash
qmake -o Makefile tcpq.pro
make
```

## Usage

```bash
./tcpq                    # Capture on default interface (eth0)
./tcpq -i eth0           # Capture on eth0
./tcpq -f "tcp"          # Show only TCP packets
./tcpq -f "port 80"      # Show traffic on port 80
./tcpq -f "src 10.0.0.1" # Show packets from 10.0.0.1
```

## License

MIT
