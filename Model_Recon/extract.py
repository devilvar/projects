#!/usr/bin/env python3
import scapy.all as scapy
import time
import os
import json
import math

WINDOW = 10
BLOCKS = 100
DATA_DIR = "DATA"
IFACE = "eth0"

def calculate_entropy(values):
    if not values:
        return 0.0
    freq = {v: values.count(v) for v in set(values)}
    total = len(values)
    return -sum((c/total) * math.log2(c/total) for c in freq.values())

def extract_features(pkt_list):
    feats = {
        "unique_dst_ports": 0,
        "unique_dst_ports_ratio": 0.0,
        "syn_ratio": 0.0,
        "syn_count": 0,
        "dst_ip_count": 0,
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
        "byte_count": sum(len(p) for p in pkt_list),
    }

    if not pkt_list:
        return feats

    ttls = []
    arrival_times = []
    last_ts = None
    src_ports = []
    dst_ports = set()
    dst_ips = set()
    tcp_flows = {}
    per_second = {}
    start_ts = pkt_list[0].time

    for pkt in pkt_list:
        sec = int(pkt.time - start_ts)
        per_second[sec] = per_second.get(sec, 0) + 1

        if not pkt.haslayer(scapy.IP):
            continue

        ip = pkt[scapy.IP]
        ttls.append(ip.ttl)
        dst_ips.add(ip.dst)

        if last_ts is not None:
            dt = pkt.time - last_ts
            if dt > 0.000001:
                arrival_times.append(dt)
        last_ts = pkt.time

        if pkt.haslayer(scapy.TCP):
            tcp = pkt[scapy.TCP]
            src_ports.append(tcp.sport)
            dst_ports.add(tcp.dport)

            flags = tcp.flags
            if flags.S: feats["syn_count"] += 1
            if flags.F: feats["fin_count"] += 1
            if flags.R: feats["rst_count"] += 1
            if int(flags) == 0: feats["null_flag_count"] += 1
            if flags.F and flags.P and flags.U: feats["xmas_flag_count"] += 1

            fkey = (ip.src, ip.dst, tcp.sport, tcp.dport)
            if fkey not in tcp_flows:
                tcp_flows[fkey] = {"syn": False, "fin_rst": False}
            if flags.S and not flags.A:
                tcp_flows[fkey]["syn"] = True
            if flags.F or flags.R:
                tcp_flows[fkey]["fin_rst"] = True

        elif pkt.haslayer(scapy.UDP):
            udp = pkt[scapy.UDP]
            src_ports.append(udp.sport)
            dst_ports.add(udp.dport)

    feats["unique_dst_ports"] = len(dst_ports)
    feats["dst_ip_count"] = len(dst_ips)

    if feats["pkt_count"] > 0:
        feats["unique_dst_ports_ratio"] = len(dst_ports) / feats["pkt_count"]
        feats["syn_ratio"] = feats["syn_count"] / feats["pkt_count"]

    if ttls:
        mean = sum(ttls) / len(ttls)
        var = sum((t - mean)**2 for t in ttls) / len(ttls)
        feats["ttl_mean"] = mean
        feats["ttl_std"] = math.sqrt(var)

    if arrival_times:
        mean = sum(arrival_times) / len(arrival_times)
        var = sum((x - mean)**2 for x in arrival_times) / len(arrival_times)
        feats["inter_arrival_mean"] = mean
        feats["inter_arrival_std"] = math.sqrt(var)

    feats["src_port_entropy"] = calculate_entropy(src_ports)

    if tcp_flows:
        incomplete = sum(1 for f in tcp_flows.values() if f["syn"] and not f["fin_rst"])
        feats["incomplete_handshake_ratio"] = incomplete / len(tcp_flows)
        feats["flow_count"] = len(tcp_flows)

    vals = list(per_second.values())
    if vals:
        mean = sum(vals) / len(vals)
        var = sum((v - mean)**2 for v in vals) / len(vals)
        feats["pkt_rate_variation"] = math.sqrt(var)

    return feats

def main():
    label = input("Enter label: ").strip()

    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)

    filename = os.path.join(DATA_DIR, f"{label}.json")
    dataset = []

    for i in range(1, BLOCKS + 1):
        print(f"\n[{i}/{BLOCKS}] Capturing {WINDOW} seconds...")
        pkts = scapy.sniff(iface=IFACE, timeout=WINDOW, store=True)
        pkt_count = len(pkts)
        pps = pkt_count / WINDOW
        print(f"Packets: {pkt_count}, PPS: {pps:.2f}")

        feats = extract_features(pkts)
        feats["label"] = label
        dataset.append(feats)

        with open(filename, "w") as f:
            json.dump(dataset, f, indent=4)

    print(f"\nSaved: {filename}\n")

if __name__ == "__main__":
    main()
