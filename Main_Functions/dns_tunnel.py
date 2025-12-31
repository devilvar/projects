#!/usr/bin/env python3
import sys
import os
import math
from datetime import datetime
from collections import defaultdict
from scapy.all import DNS, DNSQR, IP, UDP

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

MAX_DOMAIN_LENGTH = 50
ENTROPY_THRESHOLD = 3.5
QUERY_RATE_THRESHOLD = 30
SUSPICIOUS_TYPES = {16, 10}

query_counter = defaultdict(int)
last_reset = datetime.now()

def calculate_entropy(s):
    if not s:
        return 0
    prob = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)

def ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def detect_tunneling(pkt):
    global last_reset

    dns_layer = None

    if pkt.haslayer(DNS):
        dns_layer = pkt[DNS]
    elif pkt.haslayer(UDP) and (pkt[UDP].sport == 53 or pkt[UDP].dport == 53):
        try:
            dns_layer = DNS(bytes(pkt[UDP].payload))
        except Exception:
            return

    if not dns_layer or not dns_layer.haslayer(DNSQR):
        return

    try:
        qname = dns_layer[DNSQR].qname.decode("utf-8", "ignore").rstrip(".")
        qtype = dns_layer[DNSQR].qtype
        src = pkt[IP].src if pkt.haslayer(IP) else "Unknown"

        labels = qname.split(".")
        if len(labels) < 2:
            return

        subdomain = "".join(labels[:-2]) or labels[0]
        entropy = calculate_entropy(subdomain)

        now = datetime.now()
        if (now - last_reset).seconds >= 60:
            query_counter.clear()
            last_reset = now

        query_counter[src] += 1
        rate = query_counter[src]

        suspicious = (
            len(qname) > MAX_DOMAIN_LENGTH and
            entropy > ENTROPY_THRESHOLD
        ) or (
            qtype in SUSPICIOUS_TYPES and
            rate > QUERY_RATE_THRESHOLD
        )

        if suspicious:
            print(f"[DNS TUNNEL] {src} -> {qname} | Entropy={entropy:.2f}")
            alerter.trigger_alert(
                "DNS_Tunneling_Attempt",
                ts(),
                f"Source: {src}",
                {
                    "Query": qname,
                    "Entropy": f"{entropy:.2f}",
                    "Rate": rate,
                    "QueryType": qtype
                }
            )

    except Exception:
        pass
