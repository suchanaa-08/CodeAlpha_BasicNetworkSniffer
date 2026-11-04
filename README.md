# Basic Network Sniffer Using Python

## Project Overview

The Basic Network Sniffer is a Python-based application that captures and analyzes live network packets using the Scapy library.

It helps understand how data travels through a network by displaying important packet information such as source IP address, destination IP address, protocols, port numbers, packet size, TCP flags, and payload information.

## Features

- Captures live network packets.
- Supports IPv4 and IPv6 packet analysis.
- Identifies TCP, UDP, ICMP, ICMPv6, and ARP protocols.
- Displays source and destination IP addresses.
- Extracts source and destination port numbers.
- Displays packet size and timestamp.
- Identifies TCP flags.
- Displays payload previews in hexadecimal and readable text formats.

## Technologies Used

- Python
- Scapy 2.8.0
- Npcap
- TCP/IP Networking

## Project Structure

```text
CodeAlpha_BasicNetworkSniffer/
│
├── sniffer.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/suchanaa-08/CodeAlpha_BasicNetworkSniffer.git
```

### 2. Navigate to the project directory

```bash
cd CodeAlpha_BasicNetworkSniffer
```

### 3. Create a virtual environment

```bash
python -m venv venv
```

### 4. Activate the virtual environment

```powershell
.\venv\Scripts\Activate.ps1
```

### 5. Install dependencies

```bash
pip install -r requirements.txt
```

### 6. Install Npcap

Windows users need Npcap for packet capturing.

Download it from: https://npcap.com/

### 7. Run the program

Open VS Code as Administrator and execute:

```bash
python sniffer.py
```

## How It Works

1. Scapy captures packets from the selected network interface.
2. Each captured packet is passed to the packet analysis function.
3. The program identifies network and transport protocol layers.
4. It extracts IP addresses, port numbers, packet size, and TCP flags.
5. It displays available payload information.

## Learning Outcomes

- Understanding network packet structures.
- Learning TCP/IP protocols.
- Understanding IPv4 and IPv6 communication.
- Learning packet capturing and analysis using Python.
- Understanding source and destination ports.
- Exploring encrypted network traffic.

## Note

- The network interface index in `sniffer.py` is specific to the development computer. Users may need to update it according to their own network interface configuration.
- HTTPS payloads are generally encrypted and cannot be read as plaintext by this basic sniffer.
- Use this application only on networks and devices you own or have permission to monitor.

## Author

Suchana Pan