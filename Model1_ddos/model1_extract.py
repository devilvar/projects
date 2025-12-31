#!/usr/bin/env python3
import time
import json
import os
import sys
import signal
import math
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP

WINDOW = 10
IFACE = "eth0"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(OUTPUT_DIR, exist_ok=True)

all_data = []
request_stop = False
start_time_global = time.time()
current_label = "Normal"

def calculate_entropy(values):
    if not values:
        return 0.0
    freq = {v: values.count(v) for v in set(values)}
    total = len(values)
    return -sum((c / total) * math.log2(c / total) for c in freq.values() if c > 0)

def capture_features(pkt_list):
    features = {
        "pkt_count": len(pkt_list),
        "byte_count": sum(len(pkt) for pkt in pkt_list),
        "unique_src_ips": 0,
        "unique_dst_ports": 0,
        "syn_count": 0,
        "syn_ack_count": 0,
        "udp_count": 0,
        "icmp_count": 0,
        "avg_pkt_size": 0.0,
        "pps": 0.0,
        "bps": 0.0,
        "syn_ratio": 0.0,
        "udp_ratio": 0.0,
        "src_ip_entropy": 0.0,

        "icmp_ratio": 0.0,
        "avg_flow_duration": 0.0,
        "unique_dst_ports_ratio": 0.0,
        "fragment_count": 0,
        "fragment_ratio": 0.0,
        "avg_fragment_size": 0.0,

        "connection_count": 0,
        "request_rate": 0.0,
        "avg_pkts_per_flow": 0.0,
        "psh_ack_ratio": 0.0,
        
        "label": current_label
    }

    src_ips = []
    dst_ports = set()
    flows = {}

    fragment_byte_count = 0
    http_request_count = 0
    psh_ack_count = 0

    for pkt in pkt_list:
        if not pkt.haslayer(IP):
            continue

        ip = pkt[IP]
        src_ips.append(ip.src)

        if ip.flags == "MF" or ip.frag > 0:
            features["fragment_count"] += 1
            fragment_byte_count += len(ip)

        flow_key = None

        if pkt.haslayer(TCP) or pkt.haslayer(UDP):
            protocol = "TCP" if pkt.haslayer(TCP) else "UDP"
            sport, dport = pkt.sport, pkt.dport
            flow_key = tuple(sorted(((ip.src, sport), (ip.dst, dport)))) + (protocol,)

            if flow_key not in flows:
                flows[flow_key] = {
                    "pkt_count": 0,
                    "start_time": pkt.time,
                    "last_time": pkt.time,
                    "has_fin_rst": False,
                }

            flows[flow_key]["pkt_count"] += 1
            flows[flow_key]["last_time"] = pkt.time

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            dst_ports.add(tcp.dport)

            if tcp.flags.S and not tcp.flags.A:
                features["syn_count"] += 1
            if tcp.flags.S and tcp.flags.A:
                features["syn_ack_count"] += 1
            if tcp.flags.P and tcp.flags.A:
                psh_ack_count += 1

            if tcp.dport == 80 and pkt.haslayer("Raw"):
                try:
                    payload = pkt["Raw"].load.decode(errors="ignore").upper()
                    if payload.startswith(("GET", "POST")):
                        http_request_count += 1
                except:
                    pass

            if tcp.flags.F or tcp.flags.R:
                if flow_key:
                    flows[flow_key]["has_fin_rst"] = True

        elif pkt.haslayer(UDP):
            dst_ports.add(pkt[UDP].dport)
            features["udp_count"] += 1

        elif pkt.haslayer(ICMP):
            features["icmp_count"] += 1

    features["unique_src_ips"] = len(set(src_ips))
    features["unique_dst_ports"] = len(dst_ports)

    if features["pkt_count"] > 0:
        features["avg_pkt_size"] = features["byte_count"] / features["pkt_count"]
        features["pps"] = features["pkt_count"] / WINDOW
        features["bps"] = features["byte_count"] / WINDOW
        features["syn_ratio"] = features["syn_count"] / features["pkt_count"]
        features["udp_ratio"] = features["udp_count"] / features["pkt_count"]
        features["src_ip_entropy"] = calculate_entropy(src_ips)
        features["icmp_ratio"] = features["icmp_count"] / features["pkt_count"]
        features["unique_dst_ports_ratio"] = len(dst_ports) / features["pkt_count"]
        features["fragment_ratio"] = features["fragment_count"] / features["pkt_count"]
        features["psh_ack_ratio"] = psh_ack_count / features["pkt_count"]

        if features["fragment_count"] > 0:
            features["avg_fragment_size"] = fragment_byte_count / features["fragment_count"]

        if flows:
            total_duration = sum(f["last_time"] - f["start_time"] for f in flows.values())
            total_pkts = sum(f["pkt_count"] for f in flows.values())

            features["avg_flow_duration"] = total_duration / len(flows)
            features["avg_pkts_per_flow"] = total_pkts / len(flows)
            features["connection_count"] = sum(
                1 for k, v in flows.items() if k[2] == "TCP" and not v["has_fin_rst"]
            )

        features["request_rate"] = http_request_count / WINDOW

    return features

def signal_handler(sig, frame):
    global request_stop
    if not request_stop:
        print("\nStopping after current window...")
        request_stop = True
        remaining = WINDOW - (time.time() - start_time_global)
        remaining = max(1, int(remaining))
        for i in range(remaining, 0, -1):
            print(f"⏳ {i}s remaining...", end="\r")
            time.sleep(1)
        print("\nSaving...")

def select_label():
    print("\n--- DATA COLLECTION SETUP ---")
    print("Select the label for this capture session:")
    print("1. Normal")
    print("2. HTTP_DDoS_Attack")
    print("3. SYN_DDoS_Attack")
    print("4. UDP_DDoS_Attack")
    print("5. Teardown_Attack") 
    
    choice = input("\nEnter choice (1-5): ").strip()
    
    mapping = {
        "1": "Normal",
        "2": "HTTP_DDoS_Attack",
        "3": "SYN_DDoS_Attack",
        "4": "UDP_DDoS_Attack",
        "5": "Teardown_Attack"
    }
    
    return mapping.get(choice, "Normal")

def collect_test_dataset():
    global request_stop, start_time_global, current_label, OUTPUT_FILE

    current_label = select_label()
    
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"{current_label}_{timestamp}.json"
    OUTPUT_FILE = os.path.join(OUTPUT_DIR, filename)

    print(f"\n========================================")
    print(f" LABEL SELECTED: {current_label}")
    print(f" SAVING TO:      {OUTPUT_FILE}")
    print(f"========================================")
    print(f"Capturing on '{IFACE}'... Press CTRL+C to stop.\n")

    while not request_stop:
        start_time_global = time.time()
        packets = sniff(iface=IFACE, timeout=WINDOW, store=True)

        if packets:
            features = capture_features(packets)
            all_data.append(features)
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Captured {features['pkt_count']} pkts | Label: {features['label']}")

    try:
        with open(OUTPUT_FILE, "w") as f:
            json.dump(all_data, f, indent=4)
        print(f"\nSuccessfully saved {len(all_data)} windows to:")
        print(f"   {OUTPUT_FILE}")
    except Exception as e:
        print(f"\nFailed to save file: {e}")

    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    collect_test_dataset()
