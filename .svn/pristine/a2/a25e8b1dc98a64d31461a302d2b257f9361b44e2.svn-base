# tcpq Architecture

## Overview
tcpq is a Qt-based network packet analyzer that provides a graphical interface for packet capture and analysis.

## Components

### PacketCapture
- Uses libpcap for low-level packet capture
- Handles network interface selection
- Applies BPF filters
- Emits packetCaptured() signal with raw data

### PacketAnalyzer
- Parses IP, TCP, UDP, ICMP headers
- Extracts source/destination addresses and ports
- Generates human-readable packet info
- Emits packetAnalyzed() with structured PacketInfo

## Data Flow
1. PacketCapture receives raw packet from libpcap
2. Emits packetCaptured() signal
3. PacketAnalyzer receives signal and parses headers
4. Emits packetAnalyzed() with PacketInfo struct
5. GUI displays the analyzed packet
