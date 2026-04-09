# Lightweight Real-Time Intrusion Detection System (IDS)

## Project Description

My name is Ritvik Indupuri, a freshman studying Computer Information Technology at Purdue University, and this is my Raspberry Pi project for CNIT 176. I have a keen interest in cloud security and aspire to work as a Cloud Security Engineer in the near future.

The business case for this project is built on a striking statistic: **40% of cyberattacks begin with reconnaissance**—silent scans that often go completely unnoticed. While large enterprises have the infrastructure to detect these early stages, most networks at home, on campus, or in small offices lack visibility into this phase. According to IBM's X-Force Threat Intelligence Index, nearly four in ten attacks start this way, long before malware or exploits are used.

To address this gap, I developed a lightweight, real-time Intrusion Detection System (IDS) using a Raspberry Pi, Python, and the Scapy library. Think of this IDS as a motion detector at your network's front door. Sitting at the edge of the network before any firewall or endpoint, it monitors inbound traffic and focuses on two key reconnaissance patterns: **ICMP Echo Requests (pings)** and **TCP SYN packets (stealth port scans)**. Designed for low-budget setups or environments lacking enterprise-grade tools, this completely offline system spots attackers early and instantly logs their activity.

## Key Features

* **Real-Time Traffic Sniffing:** Monitors network interfaces to detect inbound reconnaissance immediately.
* **ICMP Echo Detection:** Identifies and logs basic ping probes used to check if a host is online.
* **TCP SYN Scan Detection:** Extracts target ports and IPs from stealth port scans (often performed via Nmap).
* **Live Streaming Logs:** Instantly flushes alerts to `ids_alerts.log`, allowing live viewing via `tail -f`.
* **Edge Deployment:** Operates at the network's edge for early detection.
* **Offline Processing:** Everything runs locally and instantly for maximum stability and privacy.

## System Architecture

<div align="center">
  <h3>System Architecture Diagram</h3>
</div>

```mermaid
flowchart TD
    A[Attacker Network/Laptop] -->|Inbound Packets| B(Wireless Adapter / Tailscale VPN)
    B -->|Peripheral I/O| C{AF_PACKET Socket}
    C -->|Raw Ethernet Frames| D[Scapy `sniff` Function]
    D -->|Interrupt-Driven I/O| E{`detect_packet()`}

    E -->|Yellow Path: ICMP Echo Request| F[Log Ping Source & Dest]
    E -->|TCP SYN Packet| G[Extract Targeted Ports & IPs]

    F --> H(Write to File Descriptor)
    G --> H(Write to File Descriptor)

    H -->|System Call| I[(ids_alerts.log)]
    I -->|`tail -f`| J[Live Terminal Output]
```

### Flow-by-Flow Diagram Explanation

* **Network Ingress:** Packets arrive from the attacker through the Pi's wireless adapter. Because Purdue's Wi-Fi blocks peer-to-peer traffic, a Tailscale mesh VPN tunnel (`tailscale0`) is used to bypass this restriction. In systems architecture (CNIT 176), the wireless adapter acts as a peripheral device handling input/output (I/O).
* **Raw Socket Access:** The packets are passed into an `AF_PACKET` socket. This utilizes memory-mapped I/O, giving user space access to the raw bytes of the Ethernet frames.
* **Detection Engine:** The script uses Scapy's `sniff` function to capture packets from the interface. This acts as interrupt-driven I/O, meaning it waits for incoming packets and responds when triggered rather than constantly polling. It sends each packet to a custom `detect_packet` function.
* **Traffic Routing:**
  * If the packet is an **ICMP echo request** (the "yellow path"), it logs the source and destination of the ping.
  * If it's a **TCP SYN packet**, it extracts the specific ports targeted and logs the scan attempt.
* **Logging and Output:** Alerts are written instantly to `ids_alerts.log` using file descriptors and system calls, interacting directly with OS and kernel-managed resources. Finally, a `tail -f` command streams this file to a live terminal for real-time visibility. All this logic runs on the Raspberry Pi's ARM Instruction Set Architecture (ISA), where the Python script is compiled into machine instructions via the fetch, decode, and execute cycle.

## Tech Stack

* **Hardware:** Raspberry Pi (ARM architecture)
* **Language:** Python 3
* **Libraries:** Scapy (`from scapy.all import *`)
* **Networking:** Tailscale (Mesh VPN), `hostapd` (Access Point mode with `nl80211` driver)
* **OS / Environment:** Linux (Raspberry Pi OS)
* **Testing Tools:** Nmap, T-Shark, Ping

## Detailed Setup Steps

Follow these steps to deploy the IDS on your own Raspberry Pi:

1. **Prepare the Network Interface:**
   * If on a restricted network (like Purdue University Wi-Fi that blocks P2P traffic), install and configure Tailscale:
     ```bash
     curl -fsSL https://tailscale.com/install.sh | sh
     sudo tailscale up
     ```
   * Note the interface name (e.g., `tailscale0`).

2. **Install Dependencies:**
   * Ensure Python 3 is installed.
   * Install the Scapy library. (If you face import errors, ensure all dependencies are met):
     ```bash
     sudo apt update
     sudo apt install python3-scapy
     ```

3. **Prepare the Log File:**
   * Manually create the log file to prevent "File Not Found" errors and assign the correct permissions:
     ```bash
     touch ~/ids_alerts.log
     chmod 666 ~/ids_alerts.log
     ```

4. **Run the IDS Script:**
   * **Crucial:** Scapy requires root access to sniff packets. If you forget `sudo`, it will fail silently.
   * Run the detection script (ensure your script switches to `from scapy.all import *`):
     ```bash
     sudo python3 pi_ids.py
     ```

5. **View Live Alerts:**
   * Open a second terminal session on your Pi and stream the log file to see alerts instantly:
     ```bash
     tail -f ~/ids_alerts.log
     ```

6. **Test the System (From Attacker Machine):**
   * **Ping Probe:** Send ICMP requests: `ping <Raspberry_Pi_IP>`
   * **Stealth Scan:** Run an Nmap SYN scan targeting specific ports (e.g., SSH, HTTP, HTTPS):
     ```bash
     nmap -Pn -sS -p 22,80,443 <Raspberry_Pi_IP>
     ```

*(Note: If configuring the Pi as an Access Point, ensure `hostapd.conf` is properly set up and the `nl80211` Linux driver is added, otherwise the service will crash.)*

## Live Demonstration

### Attacker Perspective: Launching the Scan

<div align="center">
  <h3>Figure 1: Attacker PowerShell Terminal Output</h3>
  <img src="https://i.imgur.com/n16WkA5.png" alt="PowerShell terminal output launching the attack">
</div>

**Explanation:** In this screenshot, the attacker (my Windows laptop) is simulating a reconnaissance phase. First, the `ping` command is used to send ICMP echo requests directly to the Raspberry Pi to check if the host is online. Next, a stealth TCP SYN scan is launched using Nmap (`nmap -Pn -sS -p 22,80,443`) to probe for open ports specifically targeting SSH (22), HTTP (80), and HTTPS (443).

### Defender Perspective: The IDS at Work

<div align="center">
  <h3>Figure 2: Pi-Terminal IDS Output</h3>
  <img src="https://i.imgur.com/anqb8hm.png" alt="PI-terminal screen image showing IDS output">
</div>

**Explanation:** On the Raspberry Pi, two terminals are running side-by-side. The terminal on the right runs the Python detection script via `sudo`, capturing and parsing the incoming packets in real time. The terminal on the left uses the `tail -f ~/ids_alerts.log` command to instantly print the appended logs. As soon as the Pi receives the ping packets and the Nmap SYN packets, the alerts populate on both screens, detailing the attack type, the source IP, the targeted ports, and exactly when the scan occurred. This confirms the system successfully caught the reconnaissance traffic at the network's edge with no delays.

---
*Future enhancements for this project include creating a systemd service to run the IDS on boot without manual `sudo` execution, expanding detection to UDP and HTTP payloads, rotating logs, and integrating with AWS CloudWatch (after resolving malformed IAM signature exceptions).*
