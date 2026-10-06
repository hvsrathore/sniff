# Python Network Packet Sniffer

A custom network packet sniffer written in raw Python using the standard `socket` and `struct` libraries. This script captures and decodes raw network traffic traversing the network interface, unpacking Ethernet frames, IP packets (IPv4/IPv6), and transport layer protocols (TCP, UDP, and ICMP).

## Features

- **Ethernet Frame Parsing:** Unpacks raw MAC addresses and identifies Ethernet types (IPv4, IPv6, ARP, VLAN).
- **IP Packet Decoding:** Parses IPv4 and IPv6 headers, extracting source/destination IP addresses and transport protocol types.
- **Transport Layer Analysis:** 
  - **TCP:** Extracts source and destination ports, payload size, and TCP flags (FIN, SYN, RST, PSH, ACK, URG).
  - **UDP:** Extracts source and destination ports and payload size.
  - **ICMP:** Identifies ICMP packet types such as Echo Requests and Echo Replies (Pings).
- **Human-Readable Logging:** Prints formatted single-line logs outlining the packet traversal (e.g., MAC addresses, IPs, Ports, and Flags).

## Prerequisites

- **Python 3.10+**: The script utilizes modern Python `match-case` syntax.
- **Root / Administrator Privileges:** The script requires `sudo` or Administrator access to open raw sockets (`SOCK_RAW`). It will throw a `PermissionError` if run without proper privileges.
- **Linux/Unix Environment:** The `socket.AF_PACKET` family is generally native to Linux platforms.

## Installation

1. Clone or download the script to your local machine.
2. Ensure you have Python 3 installed.
3. No third-party dependencies (like `scapy`) are required, as it relies purely on the standard Python libraries (`sys`, `socket`, `struct`).

## Usage

Run the script from your terminal with root/sudo permissions:

```bash
sudo python3 sniffer.py
