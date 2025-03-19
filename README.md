# Network Packet Sniffer

A lightweight Python-based packet sniffer that captures and analyzes network traffic. This tool allows you to inspect different types of network packets including Ethernet frames, IPv4, ICMP, TCP, UDP, and ARP packets.

## Features

- Capture raw network packets in real-time
- Decode and display Ethernet frame information
- Parse and analyze IPv4 packets
- Examine ICMP packets and their attributes
- Inspect TCP segments including source/destination ports
- Analyze UDP segments and their properties
- Decode ARP packets and their operations

## Requirements

- Python 3.x
- Root/Administrator privileges (required to capture raw packets)
- Linux operating system (uses AF_PACKET which is Linux-specific)

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/packet-sniffer.git
   cd packet-sniffer
   ```

2. No additional dependencies required as the script uses only Python's standard libraries.

## Usage

The packet sniffer requires root privileges to capture raw packets:

```bash
sudo python3 sniffer.py
```

The sniffer will start capturing packets and display their details in the terminal. Press Ctrl+C to stop the sniffer.

## Example Output

```
Ethernet Frame:
Destination: aa:bb:cc:dd:ee:ff, Source: 11:22:33:44:55:66, Protocol: 8

IPv4 Packet:
Version: 4, Header Length: 20, TTL: 64, Protocol: 6, Source: 192.168.1.5, Destination: 93.184.216.34

TCP Segment:
Source Port: 54321, Destination Port: 443, Sequence: 1234567890

Data:
    4500003c1c4640004006ac0bc0a80105...
```

## Protocol Support

- **Ethernet**: Decodes MAC addresses and identifies the encapsulated protocol
- **IPv4**: Extracts IP header information including addresses, TTL, and next protocol
- **ICMP**: Identifies ICMP message types and codes
- **TCP**: Extracts port numbers and sequence information
- **UDP**: Decodes source and destination ports
- **ARP**: Decodes hardware and protocol addresses for ARP operations

## Limitations

- Currently only works on Linux systems
- Does not reassemble fragmented packets
- Limited protocol support (no IPv6, no application layer protocols)

## License

[MIT](LICENSE)
