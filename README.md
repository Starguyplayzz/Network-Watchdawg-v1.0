# Network Watchdawg v1.0 📡🛡️

A powerful, low-level Network Intrusion Detection System (NIDS) and Packet Analysis Suite built from scratch in C. 

Network Watchdawg was developed to bridge the gap between high-level network tools and raw hardware communication. By interfacing directly with the Linux kernel, it provides a "ground-truth" view of every byte moving across the network interface.

## 🚀 Overview
Network Watchdawg operates in **Promiscuous Mode**, allowing it to capture and dissect traffic not just for the host machine, but for the entire network segment. It is a 2-in-1 tool designed for:
1. **Passive Monitoring:** Acting as a Mini-IDS to flag specific signatures (like DNS queries).
2. **MITM Interception:** Serving as a decoding engine for Man-in-the-Middle traffic analysis.

## ✨ Key Features
* **Deep Packet Inspection (DPI):** Manually parses and extracts data from Ethernet, IP, TCP, and UDP headers.
* **Signature-Based Detection:** Specialized module for targeted detection (e.g., DNS-based game signatures on Port 53).
* **Kernel Filtering:** Implements Berkeley Packet Filters (BPF) to ensure high-performance sniffing with minimal CPU overhead.
* **Live Identity Mapping:** Extracts Source/Destination MAC and IP pairings to map device fingerprints on a local network.
* **Payload Extraction:** Attempts to decode binary payloads into human-readable ASCII text for real-time stream monitoring.

## 🛠️ Technical Stack
* **Language:** C
* **Core Library:** `libpcap`
* **Environment:** Linux (Tested on Ubuntu/Kali)
* **Protocols Handled:** Ethernet (Layer 2), IPv4 (Layer 3), TCP & UDP (Layer 4).

## 📥 Installation & Usage

### Prerequisites
You must have the `libpcap` development headers installed on your Linux system:
```bash
sudo apt-get update
sudo apt-get install libpcap-dev
