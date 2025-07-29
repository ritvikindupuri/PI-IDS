# 🍓 Raspberry Pi Intrusion Detection System (IDS)

As part of my work in CNIT 17600 (Information Technology Architectures), I developed a fully functional IDS on a Raspberry Pi to detect early-stage reconnaissance traffic—such as ICMP pings and TCP SYN scans—commonly used by attackers to map networks.

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

## 📊 Architecture Diagram (Rendered with Mermaid)

```mermaid
flowchart TD
    A[Attacker<br>nmap/ping/hping3] --> B[Tailscale VPN]
    B --> C[Raspberry Pi IDS]
    C --> D[Scapy Sniffer<br>AF_PACKET Layer]
    C --> E[Real-time Alert Console]
    C --> F[ids_alerts.log<br>Ping/SYN logs]
