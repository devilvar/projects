#!/usr/bin/env python3
import os
import sys
from datetime import datetime
from scapy.all import sniff
import threading

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
sys.path.insert(0, BASE_DIR)

import ddos_pipeline
import Host_discovery
import Brute_force

IFACE = "eth0"
WINDOW = 10

rolling_pps_state = {"pps": None}

def ddos_worker(packets):
    try:
        result, _ = ddos_pipeline.process_ddos_packets(packets, rolling_pps_state)
        print(f"   --> DDoS/Recon Result: {result}")
    except Exception as e:
        print(f"[DDOS WORKER ERROR] {e}")

def host_discovery_worker(packets):
    try:
        Host_discovery.detect_network_scan(packets)
    except Exception as e:
        print(f"[HOST DISCOVERY ERROR] {e}")

def brute_force_worker(packets):
    try:
        Brute_force.detect_brute_force(packets)
    except Exception as e:
        print(f"[BRUTE FORCE ERROR] {e}")

def main():
    print(f"MAIN DETECTION STARTED on {IFACE}")
    print(f"   Window Size: {WINDOW} seconds")
    print(f"   Modules: DDoS (RF/GB) + Recon (RF) + Host Discovery (Logic) + Brute Force (Logic)")
    print("-" * 50)

    while True:
        try:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Sniffing window...")
            packets = sniff(iface=IFACE, timeout=WINDOW, store=True)

            if not packets:
                print("   No packets captured.")
                continue

            t_ddos = threading.Thread(target=ddos_worker, args=(packets,), daemon=True)
            t_ddos.start()

            t_host = threading.Thread(target=host_discovery_worker, args=(packets,), daemon=True)
            t_host.start()

            t_brute = threading.Thread(target=brute_force_worker, args=(packets,), daemon=True)
            t_brute.start()

        except KeyboardInterrupt:
            print("\nIDS Stopped by user.")
            sys.exit(0)

        except Exception as e:
            print(f"[MAIN ERROR] {e}")
            continue

if __name__ == "__main__":
    main()
