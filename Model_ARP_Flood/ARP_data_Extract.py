#!/usr/bin/env python3
import os
import json
import time
from datetime import datetime
from scapy.all import sniff, ARP

# ============================================================
# PATH SETUP
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "DATA")
os.makedirs(DATA_DIR, exist_ok=True)

WINDOW = 10
IFACE = "eth0"

def extract_arp_features(packets):

    timestamps = [pkt.time for pkt in packets if pkt.haslayer(ARP)]

    # Intervals
    intervals = []
    for i in range(1, len(timestamps)):
        dt = timestamps[i] - timestamps[i - 1]
        if dt >= 0:
            intervals.append(dt)

    def mean(v):
        return sum(v) / len(v) if v else 0.0

    def variance(v):
        if not v:
            return 0.0
        m = mean(v)
        return sum((x - m)**2 for x in v) / len(v)

    # Basic fields
    arp_count = len(packets)
    senders = {}
    targets = {}
    broadcasts = 0
    ip_to_mac = {}
    mac_conflicts = 0

    for pkt in packets:
        if not pkt.haslayer(ARP):
            continue

        a = pkt[ARP]

        senders[a.psrc] = senders.get(a.psrc, 0) + 1
        targets[a.pdst] = targets.get(a.pdst, 0) + 1

        if a.hwdst == "ff:ff:ff:ff:ff:ff":
            broadcasts += 1

        ip = a.psrc
        mac = a.hwsrc.lower()

        if ip not in ip_to_mac:
            ip_to_mac[ip] = mac
        elif ip_to_mac[ip] != mac:
            mac_conflicts += 1

    features = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "arp_count": arp_count,
        "unique_senders": len(senders),
        "unique_targets": len(targets),
        "broadcast_count": broadcasts,
        "broadcast_ratio": broadcasts / arp_count if arp_count > 0 else 0,
        "mac_conflict_count": mac_conflicts,
        "mac_conflict_ratio": mac_conflicts / arp_count if arp_count > 0 else 0,
        "mean_interval": mean(intervals),
        "variance_interval": variance(intervals),
        "interval_count": len(intervals)
    }

    return features

def print_realtime_summary(f):
    print("")
    print("=============================================================")
    print(f" REAL-TIME ARP WINDOW SUMMARY  ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')})")
    print("=============================================================")
    print(f" ARP Count           : {f['arp_count']}")
    print(f" Unique Senders      : {f['unique_senders']}")
    print(f" Unique Targets      : {f['unique_targets']}")
    print(f" Broadcast Count     : {f['broadcast_count']}")
    print(f" Broadcast Ratio     : {f['broadcast_ratio']:.3f}")
    print(f" MAC Conflicts       : {f['mac_conflict_count']}")
    print(f" Mean Interval (sec) : {f['mean_interval']:.6f}")
    print(f" Interval Variance   : {f['variance_interval']:.6f}")
    print("-------------------------------------------------------------")

    # Hints
    if f["arp_count"] > 2000 or f["broadcast_ratio"] > 0.90:
        print(">>> Potential ARP Flooding (High ARP count / broadcast spam)")
    if f["mac_conflict_count"] > 3:
        print(">>> Possible spoofing signatures (MAC conflicts detected)")
    if f["mean_interval"] < 0.01:
        print(">>> High-rate ARP spam (very small inter-packet time)")
    print("=============================================================\n")


def main():

    print("Select Capture Mode:")
    print("1. NORMAL")
    print("2. ARP_FLOOD ATTACK")
    choice = input("Enter choice: ")

    if choice == "1":
        LABEL = "Normal"
    elif choice == "2":
        LABEL = "ARP_Flood"
    else:
        print("Invalid choice.")
        return

    filename = f"{LABEL}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    filepath = os.path.join(DATA_DIR, filename)
    dataset = []

    print(f"\nSaving to: {filepath}")
    print("Capturing 100 windows...\n")

    for i in range(100):
        packets = sniff(filter="arp", iface=IFACE, timeout=WINDOW, store=True)
        features = extract_arp_features(packets)
        features["label"] = LABEL

        dataset.append({"features": features})

        print_realtime_summary(features)

        with open(filepath, "w") as f:
            json.dump(dataset, f, indent=2)

    print(f"\nCompleted. File saved: {filepath}")


if __name__ == "__main__":
    main()
