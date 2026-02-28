Python Deep Packet Inspection (DPI) Tool



A lightweight network sniffer and protocol analyzer built with Scapy. This tool goes beyond standard packet sniffing by performing Deep Packet Inspection—identifying application-layer protocols by checking payload signatures even when they run on non-standard ports.

🚀 Features

Real-time Sniffing: Captures live traffic from any available network interface.

Protocol Identification:

Port-based: Maps common ports (22, 80, 443, etc.) to their respective services.

Signature-based (DPI): Scans packet payloads for text and binary signatures to identify protocols like HTTP, SSH, TLS, and FTP.

Dual-Payload Extraction: Automatically attempts to decode payloads as UTF-8 text while falling back to Hex strings for binary data.

Visual Color-Coding: High-contrast terminal output to easily distinguish between different protocols (e.g., Green for HTTP, Red for SSH).

JSON Logging: Automatically saves all captured packet data to packet_log.json for later analysis.



🛠️ Requirements


Python 3.x

Scapy Library: pip install scapy

Root/Admin Privileges: Network sniffing requires elevated permissions (e.g., sudo).



📋 How It Works



The tool follows a multi-step logic to identify traffic:

Port Mapping: Checks the source and destination ports against a PORT_MAP.

Text Analysis: Searches for string signatures like GET, POST, or SSH- in decoded payloads.

Binary Analysis: Searches for magic bytes (e.g., TLS handshake versions or ZIP headers).

Logging: Stores IP addresses, MAC addresses, TCP/UDP flags, and payload previews.



🖥️ Usage



Clone or download the DPI.py script.

Run with sudo/Administrator privileges:

Select Interface: The script will list available interfaces (e.g., eth0, wlan0, lo). Type the name of the one you wish to monitor.

Set Limit: Enter the number of packets to capture, or 0 for infinite.


⚠️ Disclaimer

This tool is for educational and network troubleshooting purposes only. Use it only on networks where you have explicit permission to monitor traffic.

