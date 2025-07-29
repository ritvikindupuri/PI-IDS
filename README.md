
# 🍓 Raspberry Pi Intrusion Detection System (IDS)

A lightweight Python-based IDS built for edge networks using a Raspberry Pi, designed to detect **early-stage reconnaissance traffic** such as ICMP ping sweeps and TCP SYN scans. Built and tested as part of Purdue's CNIT 17600 course.

---

## 🔍 What It Does

| Feature                            | Description                                                                 |
|------------------------------------|-----------------------------------------------------------------------------|
| 📡 Packet Sniffing                | Uses Scapy to capture network packets in real time                         |
| 🛡️ Threat Detection               | Detects ICMP Echo Requests and TCP SYN packets (reconnaissance attempts)   |
| 📝 Logging                        | Alerts are written to both the terminal and a local log file               |
| ⚙️ Protocol Support              | Supports ICMP, TCP (SYN flags)                                             |
| 🧪 Validation                     | Tested using tshark, nmap, ping, and hping3                                |

---

## 📊 Architecture Diagram

```text
+----------------------------+
|     Windows Attacker      |
|---------------------------|
| ping / nmap / hping3      |
+-------------+-------------+
              |
              v
+----------------------------+
|      Tailscale VPN        |
|  (connects devices in lab)|
+-------------+-------------+
              |
              v
+----------------------------+
|     Raspberry Pi IDS      |
|---------------------------|
| - Scapy sniffer           |
| - Custom packet handler   |
| - Logs alerts to file     |
| - Displays live alerts    |
+-------------+-------------+
              |
              v
+----------------------------+
|     ids_alerts.log        |
| - Saved alerts:           |
|   - Ping sweeps           |
|   - SYN scans             |
+----------------------------+



🧪 Tech Stack
Language: Python 3

Libraries: scapy, datetime, os

Tools Used: tshark, nmap, ping, PowerShell, hping3

Hardware: Raspberry Pi 4

Interface: tailscale0 (VPN)
