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

## 📊 Architecture Diagram

```text
                        +------------------------+
                        |    Attacker (Windows)  |
                        | ping, nmap, hping3     |
                        +-----------+------------+
                                    |
                                    v
                          +---------+----------+
                          |   Tailscale VPN     |
                          | (secure interface)  |
                          +---------+----------+
                                    |
                                    v
                +-------------------+---------------------+
                |              Raspberry Pi IDS           |
                |------------------------------------------|
                | - Python + Scapy                        |
                | - Custom packet sniffer (AF_PACKET)     |
                | - Detects ICMP Echo & TCP SYN           |
                | - Alerts in terminal & logs to file     |
                +-------------------+---------------------+
                                    |
                                    v
                          +---------+----------+
                          |  ids_alerts.log    |
                          | Real-time logs:    |
                          | - Ping sweeps      |
                          | - SYN scans        |
                          +--------------------+
