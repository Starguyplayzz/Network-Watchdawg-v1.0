# Network Watchdawg v1.0 📡🛡️

A powerful, low-level Network Intrusion Detection System (NIDS) and Packet Analysis Suite built from scratch in C.

Network Watchdawg bridges the gap between high-level network tools and raw hardware communication. By interfacing directly with the Linux kernel, it provides a **ground-truth view of every byte** moving across the network interface.

---

## 🚀 Overview

Network Watchdawg operates in **Promiscuous Mode**, allowing it to capture and dissect traffic not just for the host machine, but for the entire network segment.

It is a 2-in-1 tool designed for:

1. **Passive Monitoring:** Acting as a Mini-IDS to flag specific signatures (e.g., DNS queries, domain detection).
2. **MITM Interception:** Serving as a decoding engine for Man-in-the-Middle traffic analysis.

---

## ✨ Key Features

* **Deep Packet Inspection (DPI):** Manually parses Ethernet, IP, TCP, and UDP headers.
* **Signature-Based Detection:** Detects specific patterns like domain names (e.g., gaming websites) from packet payloads.
* **Kernel-Level Filtering:** Uses Berkeley Packet Filters (BPF) for efficient packet capture.
* **Live Identity Mapping:** Extracts Source/Destination MAC & IP addresses for device tracking.
* **Payload Analysis:** Converts raw binary payloads into readable ASCII for real-time inspection.

---

## 🛠️ Technical Stack

* **Language:** C
* **Core Library:** `libpcap`
* **Environment:** Linux (Tested on Ubuntu/Kali)
* **Protocols:** Ethernet (L2), IPv4 (L3), TCP & UDP (L4)

---

## 📥 Installation & Usage

### Prerequisites

Install the required library:

```bash
sudo apt-get update
sudo apt-get install libpcap-dev
```

---

## ⚙️ Compilation

Use `gcc` with the `-lpcap` flag to link the libpcap library:

```bash
gcc Network_WatchDawg.c -o Network_WatchDawg -lpcap
```

---

## ▶️ Running the Program

```bash
sudo ./Network_WatchDawg
```

---

## 🔐 Why `sudo` is Required?

Network Watchdawg interacts directly with **network interfaces in promiscuous mode**, which is a **privileged operation** in Linux.

Running with `sudo` is required because:

* It allows access to **raw sockets**
* It enables **packet sniffing at kernel level**
* It allows switching the network interface to **promiscuous mode**
* Normal users are restricted from capturing packets for **security reasons**

Without root privileges, `libpcap` will fail to capture packets.

---

## ⚠️ Disclaimer

This tool is intended strictly for:

* Educational purposes
* Authorized lab environments
* Ethical security testing

Do not use it on networks without proper permission.

---

## 🧠 Author Note

This project reflects a deep understanding of how data flows at the packet level. It is not just a tool, but a step toward thinking like a **network security engineer**.
