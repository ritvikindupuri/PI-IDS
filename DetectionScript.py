from scapy.all import sniff, IP, TCP, ICMP
import os
from datetime import datetime

LOG_FILE = os.path.expanduser("~/ids_alerts.log")

def detect_packet(pkt):
    alert = None

    if pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        if icmp.type == 8:
            alert = f"[{datetime.now()}] Ping detected from {pkt[IP].src}"

    elif pkt.haslayer(TCP):
        tcp = pkt[TCP]
        if tcp.flags & 0x02:
            alert = f"[{datetime.now()}] SYN packet from {pkt[IP].src}:{tcp.sport} to {pkt[IP].dst}:{tcp.dport}"

    if alert:
        print(alert)
        with open(LOG_FILE, "a") as f:
            f.write(alert + "\n")
            f.flush()

print("Starting IDS... Press Ctrl+C to stop.")
sniff(filter="icmp or tcp", prn=detect_packet, store=0)
