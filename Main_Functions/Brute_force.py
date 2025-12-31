#!/usr/bin/env python3
import sys
import os
import time
from collections import defaultdict
from scapy.all import IP, TCP, sniff
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

SENSITIVE_PORTS = {21, 22, 23, 445, 3389}

BURST_THRESHOLD = 5
SLOW_THRESHOLD = 10
TOTAL_ATTEMPT_LIMIT = 20
HISTORY_WINDOW = 60
WINDOW = 10

attempt_history = defaultdict(list)
persistent_tracker = defaultdict(int)

def ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def detect_brute_force(packets):
    global attempt_history, persistent_tracker
    if not packets:
        return

    now = time.time()
    
    current_burst_counts = defaultdict(int)

    for pkt in packets:
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            dst_port = pkt[TCP].dport
            flags = pkt[TCP].flags
            src_ip = pkt[IP].src

            if dst_port in SENSITIVE_PORTS:
                if flags.S and not flags.A:
                    current_burst_counts[(src_ip, dst_port)] += 1
                    attempt_history[(src_ip, dst_port)].append(now)
                    persistent_tracker[src_ip] += 1

    for src_ip, total_count in persistent_tracker.items():
        if total_count >= TOTAL_ATTEMPT_LIMIT:
            print(f"Persistent Suspicious Activity: {src_ip} has tried {total_count} times total.")
            alerter.trigger_alert(
                attack_type="Multiple_Login_Attempts",
                timestamp=ts(),
                source_info=f"Suspicious IP: {src_ip}",
                details_dict={
                    "Total Attempts": total_count,
                    "Note": "Persistent login failures detected over time."
                }
            )
            persistent_tracker[src_ip] = 0

    all_suspects = set(attempt_history.keys()) | set(current_burst_counts.keys())

    for (src_ip, port) in all_suspects:
        timestamps = attempt_history[(src_ip, port)]
        valid_timestamps = [t for t in timestamps if now - t <= HISTORY_WINDOW]
        attempt_history[(src_ip, port)] = valid_timestamps
        
        long_term_count = len(valid_timestamps)
        burst_count = current_burst_counts.get((src_ip, port), 0)
        
        attack_type = None
        count_to_report = 0

        if burst_count >= BURST_THRESHOLD:
            attack_type = "Fast_Brute_Force"
            count_to_report = burst_count
        elif long_term_count >= SLOW_THRESHOLD:
            attack_type = "Slow_Brute_Force"
            count_to_report = long_term_count
        
        if attack_type:
            service = {21: "FTP", 22: "SSH", 23: "Telnet", 445: "SMB", 3389: "RDP"}.get(port, "Unknown")
            print(f"{attack_type} Detected: {src_ip} -> Port {port} ({service}) | Attempts: {count_to_report}")
            
            alerter.trigger_alert(
                attack_type=f"{service}_{attack_type}",
                timestamp=ts(),
                source_info=f"Attacker: {src_ip}",
                details_dict={
                    "Target Port": port,
                    "Attempts": count_to_report,
                    "Window": f"{HISTORY_WINDOW}s" if "Slow" in attack_type else f"{WINDOW}s",
                    "Service": service
                }
            )
            del attempt_history[(src_ip, port)]

if __name__ == "__main__":
    print(f"Brute Force Detector Started")
    print(f"Monitoring Ports: {SENSITIVE_PORTS}")
    print(f"Thresholds: Burst > {BURST_THRESHOLD}/10s, Slow > {SLOW_THRESHOLD}/60s, Total > {TOTAL_ATTEMPT_LIMIT}")
    print("Press CTRL+C to stop...")

    while True:
        try:
            packets = sniff(iface="eth0", timeout=WINDOW, store=True)
            detect_brute_force(packets)
        except KeyboardInterrupt:
            print("\nStopped.")
            sys.exit(0)
        except Exception as e:
            print(f"Error: {e}")
