import time
import json
import os
import sys
import signal
import math
from datetime import datetime
from scapy.all import sniff, IP, TCP

# -----------------------------------------
# CONFIGURATION (UPDATED FOR NEW PATH)
# -----------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(os.path.dirname(BASE_DIR), "Basic_data", "model2_data")
os.makedirs(OUTPUT_DIR, exist_ok=True)

WINDOW = 10
IFACE = "eth0"

SESSION_TS = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
OUTPUT_FILE = os.path.join(OUTPUT_DIR, f"model2_features_{SESSION_TS}.json")

all_data = []
stop_requested = False
start_time_global = time.time()


# -----------------------------------------
# UTILITY FUNCTIONS
# -----------------------------------------

def calculate_entropy(values):
    if not values:
        return 0.0
    freq = {v: values.count(v) for v in set(values)}
    total = len(values)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


# -----------------------------------------
# MODEL-2 FEATURE EXTRACTION
# -----------------------------------------

def extract_model2_features(pkt_list):

    extra = {
        "fin_count": 0,
        "rst_count": 0,
        "null_flag_count": 0,
        "xmas_flag_count": 0,
        "ttl_mean": 0.0,
        "ttl_std": 0.0,
        "inter_arrival_mean": 0.0,
        "inter_arrival_std": 0.0,
        "src_port_entropy": 0.0,
        "incomplete_handshake_ratio": 0.0,
        "pkt_rate_variation": 0.0,
        "flow_count": 0,
        "pkt_count": len(pkt_list),
        "byte_count": sum(len(pkt) for pkt in pkt_list)
    }

    if not pkt_list:
        return extra

    ttls = []
    arrival_times = []
    last_time = None
    src_ports = []
    tcp_flows = {}
    per_second = {}

    start_ts = pkt_list[0].time

    for pkt in pkt_list:

        sec = int(pkt.time - start_ts)
        per_second[sec] = per_second.get(sec, 0) + 1

        if not pkt.haslayer(IP):
            continue

        ip = pkt[IP]
        ttls.append(ip.ttl)

        if last_time is not None:
            dt = pkt.time - last_time
            if dt > 0:
                arrival_times.append(dt)
        last_time = pkt.time

        if pkt.haslayer(TCP):

            tcp = pkt[TCP]
            src_ports.append(tcp.sport)
            flags = tcp.flags

            if flags.F:
                extra["fin_count"] += 1
            if flags.R:
                extra["rst_count"] += 1
            if int(flags) == 0:
                extra["null_flag_count"] += 1
            if flags.F and flags.P and flags.U:
                extra["xmas_flag_count"] += 1

            fkey = (ip.src, ip.dst, tcp.sport, tcp.dport)
            if fkey not in tcp_flows:
                tcp_flows[fkey] = {"syn": False, "fin_rst": False}

            if flags.S and not flags.A:
                tcp_flows[fkey]["syn"] = True
            if flags.F or flags.R:
                tcp_flows[fkey]["fin_rst"] = True

    if ttls:
        mean = sum(ttls) / len(ttls)
        var = sum((t - mean) ** 2 for t in ttls) / len(ttls)
        extra["ttl_mean"] = mean
        extra["ttl_std"] = math.sqrt(var)

    if arrival_times:
        mean = sum(arrival_times) / len(arrival_times)
        var = sum((x - mean) ** 2 for x in arrival_times) / len(arrival_times)
        extra["inter_arrival_mean"] = mean
        extra["inter_arrival_std"] = math.sqrt(var)

    extra["src_port_entropy"] = calculate_entropy(src_ports)

    if tcp_flows:
        incomplete = sum(1 for f in tcp_flows.values() if f["syn"] and not f["fin_rst"])
        extra["incomplete_handshake_ratio"] = incomplete / len(tcp_flows)
        extra["flow_count"] = len(tcp_flows)

    pps_vals = list(per_second.values())
    if pps_vals:
        mean = sum(pps_vals) / len(pps_vals)
        var = sum((p - mean) ** 2 for p in pps_vals) / len(pps_vals)
        extra["pkt_rate_variation"] = math.sqrt(var)

    return extra


# -----------------------------------------
# SIGNAL HANDLING
# -----------------------------------------

def handle_signal(sig, frame):
    global stop_requested
    if not stop_requested:
        print("\nStopping after current window…")
        stop_requested = True
    else:
        print("Already stopping…")


# -----------------------------------------
# MAIN LOOP
# -----------------------------------------

def main():
    global stop_requested, start_time_global

    print(f"Capturing on '{IFACE}' — press CTRL+C to stop after current window.")

    while not stop_requested:
        start_time_global = time.time()

        packets = sniff(iface=IFACE, timeout=WINDOW, store=True)

        if packets:
            features = extract_model2_features(packets)
            all_data.append(features)
            pps = features["pkt_count"] / WINDOW
            print(f"Window captured {features['pkt_count']} packets | PPS: {pps:.2f}")
        else:
            print("No packets this window.")

    print("\nSaving dataset…")

    with open(OUTPUT_FILE, "w") as f:
        json.dump(all_data, f, indent=4)

    print(f"✔ Dataset saved: {OUTPUT_FILE}")
    print("Done.")


if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_signal)
    main()
