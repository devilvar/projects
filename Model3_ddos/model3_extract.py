import os
import sys
import time
import json
import math
import signal
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP

# ----------------------------------------------------
# PATH CONFIG
# ----------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RAW_DATA_DIR = os.path.join(BASE_DIR, "raw_data")
os.makedirs(RAW_DATA_DIR, exist_ok=True)

WINDOW = 10
IFACE = "eth0"

SESSION_TS = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
OUTPUT_FILE = os.path.join(RAW_DATA_DIR, f"model3_raw_{SESSION_TS}.json")

all_windows = []
stop_requested = False


# ----------------------------------------------------
# UTIL
# ----------------------------------------------------
def calculate_entropy(values):
    if not values:
        return 0.0
    freq = {v: values.count(v) for v in set(values)}
    total = len(values)
    return -sum((c/total) * math.log2(c/total) for c in freq.values() if c > 0)


# ----------------------------------------------------
# FEATURE EXTRACTION (Teardrop-specific)
# ----------------------------------------------------
def extract_teardrop_features(pkt_list):

    features = {
        "pkt_count": len(pkt_list),
        "byte_count": sum(len(pkt) for pkt in pkt_list),

        "fragment_count": 0,
        "fragment_ratio": 0.0,
        "avg_fragment_size": 0.0,

        "inter_arrival_mean": 0.0,
        "inter_arrival_std": 0.0,

        "ttl_mean": 0.0,
        "ttl_std": 0.0,

        "src_port_entropy": 0.0,
        "flow_count": 0,
        "udp_ratio": 0.0,

        "pkt_rate_variation": 0.0,
    }

    if not pkt_list:
        return features

    ttls = []
    arrival_times = []
    last_ts = None
    src_ports = []
    flows = {}
    fragment_bytes = 0

    per_second = {}
    start_ts = pkt_list[0].time

    for pkt in pkt_list:

        sec = int(pkt.time - start_ts)
        per_second[sec] = per_second.get(sec, 0) + 1

        if not pkt.haslayer(IP):
            continue

        ip = pkt[IP]
        ttls.append(ip.ttl)

        if last_ts is not None:
            dt = pkt.time - last_ts
            if dt > 0:
                arrival_times.append(dt)
        last_ts = pkt.time

        if ip.flags.MF or ip.frag > 0:
            features["fragment_count"] += 1
            fragment_bytes += len(ip)

        if pkt.haslayer(TCP):
            t = pkt[TCP]
            src_ports.append(t.sport)
            flows[(ip.src, ip.dst, t.sport, t.dport)] = True

        if pkt.haslayer(UDP):
            u = pkt[UDP]
            src_ports.append(u.sport)
            flows[(ip.src, ip.dst, u.sport, u.dport)] = True

    # TTL stats
    if ttls:
        mean = sum(ttls) / len(ttls)
        var = sum((t - mean) ** 2 for t in ttls) / len(ttls)
        features["ttl_mean"] = mean
        features["ttl_std"] = math.sqrt(var)

    # Inter-arrival
    if arrival_times:
        m = sum(arrival_times) / len(arrival_times)
        v = sum((x - m) ** 2 for x in arrival_times) / len(arrival_times)
        features["inter_arrival_mean"] = m
        features["inter_arrival_std"] = math.sqrt(v)

    # Fragment stats
    total_pkts = len(pkt_list)
    if total_pkts > 0:
        features["fragment_ratio"] = features["fragment_count"] / total_pkts
    if features["fragment_count"] > 0:
        features["avg_fragment_size"] = fragment_bytes / features["fragment_count"]

    # UDP ratio
    udp_count = sum(1 for pkt in pkt_list if pkt.haslayer(UDP))
    if total_pkts > 0:
        features["udp_ratio"] = udp_count / total_pkts

    # Entropy
    features["src_port_entropy"] = calculate_entropy(src_ports)

    # Flow count
    features["flow_count"] = len(flows)

    # PPS variance
    buckets = list(per_second.values())
    if buckets:
        mean_pps = sum(buckets) / len(buckets)
        var_pps = sum((b - mean_pps) ** 2 for b in buckets) / len(buckets)
        features["pkt_rate_variation"] = math.sqrt(var_pps)

    return features


# ----------------------------------------------------
# CTRL+C HANDLER
# ----------------------------------------------------
def handle_signal(sig, frame):
    global stop_requested
    if not stop_requested:
        print("\nStopping after current window…")
        stop_requested = True
    else:
        print("Already stopping…")


# ----------------------------------------------------
# MAIN LOOP
# ----------------------------------------------------
def main():
    global stop_requested

    print("\n====================================================")
    print(" MODEL-3 TEARDROP RAW DATA CAPTURE STARTED ")
    print("====================================================")
    print("Saving to   :", OUTPUT_FILE)
    print("Interface   :", IFACE)
    print("Window Size :", WINDOW)
    print("Press CTRL+C to stop...\n")

    while not stop_requested:

        packets = sniff(iface=IFACE, timeout=WINDOW, store=True)

        if packets:
            feats = extract_teardrop_features(packets)
            all_windows.append(feats)

            print(f"Captured {feats['pkt_count']} packets | Fragment Ratio = {feats['fragment_ratio']:.3f}")
        else:
            print("No packets in this window.")

    print("\nSaving dataset...")
    with open(OUTPUT_FILE, "w") as f:
        json.dump(all_windows, f, indent=4)

    print("✔ Saved:", OUTPUT_FILE)
    print("Done.\n")


# ----------------------------------------------------
# ENTRY POINT
# ----------------------------------------------------
if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_signal)
    main()
