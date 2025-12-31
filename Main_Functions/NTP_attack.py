#!/usr/bin/env python3
import sys
import os
import time
import math
import ipaddress
from collections import defaultdict
from datetime import datetime
from scapy.all import IP, UDP, sniff

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
sys.path.append(os.path.join(PROJECT_ROOT, "Basic_Functions"))

try:
    import alerter
except ImportError:
    class _Fake:
        @staticmethod
        def trigger_alert(a, b, c, d):
            print(f"[ALERT] {a} | {c}")
    alerter = _Fake()

IFACE = "eth0"
WINDOW_SECONDS = 10
MIN_LARGE_RESPONSE_SIZE = 400
MIN_RESPONSE_COUNT = 30
MIN_AMPLIFICATION_RATIO = 5.0
MIN_UNIQUE_SERVERS = 5
ALERT_COOLDOWN = 300

ntp_requests = defaultdict(int)
ntp_responses = defaultdict(int)
ntp_response_count = defaultdict(int)
ntp_sources = defaultdict(set)
last_alert_time = {}
window_start = time.time()

def ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except:
        return False

def reset_window():
    ntp_requests.clear()
    ntp_responses.clear()
    ntp_response_count.clear()
    ntp_sources.clear()

def trigger_alert(internal_ip, ratio):
    now = time.time()
    if internal_ip in last_alert_time:
        if now - last_alert_time[internal_ip] < ALERT_COOLDOWN:
            return
    last_alert_time[internal_ip] = now
    
    alerter.trigger_alert(
        attack_type="NTP_Amplification_Attack",
        timestamp=ts(),
        source_info=f"Victim: {internal_ip}",
        details_dict={
            "Response_Count": ntp_response_count[internal_ip],
            "Amplification_Ratio": "INF" if ratio == float("inf") else f"{ratio:.2f}",
            "Unique_Servers": len(ntp_sources[internal_ip]),
            "Window": f"{WINDOW_SECONDS}s"
        }
    )

def evaluate_window():
    for internal_ip in ntp_responses:
        resp_bytes = ntp_responses.get(internal_ip, 0)
        req_bytes = ntp_requests.get(internal_ip, 0)
        resp_count = ntp_response_count.get(internal_ip, 0)
        server_count = len(ntp_sources.get(internal_ip, []))

        if resp_count < MIN_RESPONSE_COUNT or server_count < MIN_UNIQUE_SERVERS:
            continue

        if req_bytes == 0:
            trigger_alert(internal_ip, float("inf"))
            continue

        ratio = resp_bytes / req_bytes
        if ratio >= MIN_AMPLIFICATION_RATIO:
            trigger_alert(internal_ip, ratio)

def process_packet(pkt):
    global window_start

    if not pkt.haslayer(IP) or not pkt.haslayer(UDP):
        return

    ip = pkt[IP]
    udp = pkt[UDP]

    if udp.sport != 123 and udp.dport != 123:
        return

    pkt_len = len(pkt)

    if udp.sport == 123 and is_private(ip.dst):
        if pkt_len < MIN_LARGE_RESPONSE_SIZE:
            return
        internal_ip = ip.dst
        ntp_responses[internal_ip] += pkt_len
        ntp_response_count[internal_ip] += 1
        if not is_private(ip.src):
            ntp_sources[internal_ip].add(ip.src)

    elif udp.dport == 123 and is_private(ip.src):
        internal_ip = ip.src
        ntp_requests[internal_ip] += pkt_len

    now = time.time()
    if now - window_start >= WINDOW_SECONDS:
        evaluate_window()
        reset_window()
        window_start = now

def main():
    print("NTP Amplification Detection Module Running")
    try:
        sniff(iface=IFACE, filter="udp port 123", prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("\nStopped.")

if __name__ == "__main__":
    main()
