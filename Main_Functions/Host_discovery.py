#!/usr/bin/env python3
import sys
import os
import subprocess
import socket
from collections import defaultdict
from scapy.all import ARP, IP, TCP, UDP, sniff
from datetime import datetime

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
sys.path.append(os.path.join(PROJECT_ROOT, "Basic_Functions"))

try:
    import alerter
except ImportError:
    class _Fake:
        @staticmethod
        def trigger_alert(a, b, c, d): print(f"[ALERT] {a} | {c}")
    alerter = _Fake()

HOST_DISCOVERY_THRESHOLD = 15
PORT_SCAN_THRESHOLD = 20
WINDOW = 10

def ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def get_gateway_ip():
    try:
        out = subprocess.check_output("ip route", shell=True).decode()
        for line in out.splitlines():
            if line.startswith("default"):
                parts = line.split()
                if len(parts) >= 3:
                    return parts[2]
    except Exception:
        pass
    return "192.168.1.1"

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

ROUTER_IP = get_gateway_ip()
MY_IP = get_local_ip()

def detect_network_scan(packets):
    if not packets:
        return

    arp_tracker = defaultdict(set)
    port_tracker = defaultdict(set)

    for pkt in packets:
        if pkt.haslayer(ARP) and pkt[ARP].op == 1:
            s_ip = pkt[ARP].psrc

            if s_ip == ROUTER_IP or s_ip == MY_IP:
                continue

            t_ip = pkt[ARP].pdst
            arp_tracker[s_ip].add(t_ip)

        if pkt.haslayer(IP):
            src_ip = pkt[IP].src

            if src_ip == ROUTER_IP or src_ip == MY_IP:
                continue

            dst_port = None
            if pkt.haslayer(TCP):
                dst_port = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                dst_port = pkt[UDP].dport
            
            if dst_port:
                port_tracker[src_ip].add(dst_port)

    for s_ip, targets in arp_tracker.items():
        count = len(targets)
        if count > HOST_DISCOVERY_THRESHOLD:
            print(f"Network Scan Detected (ARP): {s_ip} scanned {count} hosts")
            alerter.trigger_alert(
                attack_type="Network_Discovery_Scan",
                timestamp=ts(),
                source_info=f"Scanner IP: {s_ip}",
                details_dict={
                    "Method": "ARP Sweep",
                    "Hosts Targeted": count,
                    "Window": "10s"
                }
            )

    for s_ip, ports in port_tracker.items():
        count = len(ports)
        if count > PORT_SCAN_THRESHOLD:
            print(f"Port Scanning Detected: {s_ip} hit {count} unique ports")
            alerter.trigger_alert(
                attack_type="Port_Scanning_Detected",
                timestamp=ts(),
                source_info=f"Scanner IP: {s_ip}",
                details_dict={
                    "Method": "TCP/UDP Port Scan",
                    "Unique Ports": count,
                    "Window": "10s"
                }
            )

if __name__ == "__main__":
    print(f"Standalone Host/Port Discovery Detector Started")
    print(f"Whitelisted Gateway: {ROUTER_IP}")
    print(f"Whitelisted Self:    {MY_IP}")
    print(f"Thresholds: ARP > {HOST_DISCOVERY_THRESHOLD} hosts, Ports > {PORT_SCAN_THRESHOLD} ports")
    print("Press CTRL+C to stop...")

    while True:
        try:
            packets = sniff(iface="eth0", timeout=WINDOW, store=True)
            detect_network_scan(packets)
        except KeyboardInterrupt:
            print("\nStopped.")
            sys.exit(0)
        except Exception as e:
            print(f"Error: {e}")
