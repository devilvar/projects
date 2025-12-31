import json
import time
import threading
from scapy.all import sniff, TCP, IP
import math
import os

WINDOW_SECONDS = 10
TOTAL_BLOCKS = 100
OUTPUT_DIR = "DATA"


class FeatureCollector:
    def __init__(self):
        self.reset()

    def reset(self):
        self.fin_count = 0
        self.rst_count = 0
        self.null_flag_count = 0
        self.xmas_flag_count = 0
        self.ttl_values = []
        self.arrival_times = []
        self.src_ports = []
        self.handshake_total = 0
        self.handshake_failed = 0
        self.flow_set = set()
        self.pkt_count = 0
        self.byte_count = 0
        self.start_time = time.time()

    def process_packet(self, pkt):
        now = time.time()
        self.pkt_count += 1
        self.byte_count += len(pkt)
        self.arrival_times.append(now)

        if IP in pkt:
            ip = pkt[IP]
            self.ttl_values.append(ip.ttl)

            if TCP in pkt:
                tcp = pkt[TCP]
                flow_key = (ip.src, ip.dst, tcp.sport, tcp.dport)
                self.flow_set.add(flow_key)

                self.src_ports.append(tcp.sport)
                flags = tcp.flags

                if flags & 0x01:
                    self.fin_count += 1
                if flags & 0x04:
                    self.rst_count += 1
                if flags == 0:
                    self.null_flag_count += 1
                if flags & 0x29 == 0x29:
                    self.xmas_flag_count += 1

                self.handshake_total += 1
                if not (flags & 0x02):  # not SYN
                    self.handshake_failed += 1


def capture_window(collector):
    sniff(timeout=WINDOW_SECONDS, prn=collector.process_packet, store=False)


def compute_features(col):
    # TTL stats
    ttl_mean = sum(col.ttl_values) / len(col.ttl_values) if col.ttl_values else 0
    ttl_std = (
        math.sqrt(sum((x - ttl_mean) ** 2 for x in col.ttl_values) / len(col.ttl_values))
        if len(col.ttl_values) > 1 else 0
    )

    # Inter-arrival
    inter_arr = []
    arr = col.arrival_times
    if len(arr) > 1:
        for i in range(1, len(arr)):
            inter_arr.append(arr[i] - arr[i - 1])

    inter_arr_mean = sum(inter_arr) / len(inter_arr) if inter_arr else 0
    inter_arr_std = (
        math.sqrt(sum((x - inter_arr_mean) ** 2 for x in inter_arr) / len(inter_arr))
        if len(inter_arr) > 1 else 0
    )

    # Entropy
    def entropy(vals):
        if not vals:
            return 0
        counts = {}
        for v in vals:
            counts[v] = counts.get(v, 0) + 1
        total = len(vals)
        return -sum((c/total) * math.log2(c/total) for c in counts.values())

    src_port_entropy = entropy(col.src_ports)

    # Flow count
    flow_count = len(col.flow_set)

    # Packet rate variation
    pkt_rate_variation = inter_arr_std * 10000

    # Incomplete handshake ratio
    incomplete_ratio = 0
    if col.handshake_total > 0:
        incomplete_ratio = col.handshake_failed / col.handshake_total

    return {
        "fin_count": col.fin_count,
        "rst_count": col.rst_count,
        "null_flag_count": col.null_flag_count,
        "xmas_flag_count": col.xmas_flag_count,
        "ttl_mean": ttl_mean,
        "ttl_std": ttl_std,
        "inter_arrival_mean": inter_arr_mean,
        "inter_arrival_std": inter_arr_std,
        "src_port_entropy": src_port_entropy,
        "incomplete_handshake_ratio": incomplete_ratio,
        "pkt_rate_variation": pkt_rate_variation,
        "flow_count": flow_count,
        "pkt_count": col.pkt_count,
        "byte_count": col.byte_count
    }


def main():
    print("\nDataset Builder (Two-Stage Verification Model)")
    print("---------------------------------------------")

    # Ask label ONE time
    while True:
        global_label = input("Enter label for all 100 blocks (Normal / Mixed_Attack): ").strip()
        if global_label in ["Normal", "Mixed_Attack"]:
            break
        print("Invalid input. Enter either Normal or Mixed_Attack.")

    # Prepare output dir
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    output_path = os.path.join(OUTPUT_DIR, global_label + ".json")
    all_blocks = []

    print(f"\nSaving dataset into: {output_path}\n")

    for i in range(TOTAL_BLOCKS):
        print(f"[+] Capturing block {i+1}/100 for {WINDOW_SECONDS} seconds ...")

        collector = FeatureCollector()
        capture_window(collector)

        # Compute features
        features = compute_features(collector)
        features["label"] = global_label

        # Saving block into memory list
        all_blocks.append(features)

        # Show only minimal console info
        pps = collector.pkt_count / WINDOW_SECONDS
        print(f"    Packets: {collector.pkt_count}   PPS: {pps:.2f}")

    # Save the entire dataset in one JSON file
    with open(output_path, "w") as f:
        json.dump(all_blocks, f, indent=4)

    print("\nDataset collection complete.")
    print(f"File saved: {output_path}")


if __name__ == "__main__":
    main()
