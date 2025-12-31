#!/usr/bin/env python3
import time
import threading
import sys
import os
from collections import defaultdict, deque
from datetime import datetime
from statistics import mode
from scapy.all import IP, IPv6, UDP, TCP, DNS, DNSQR

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
sys.path.append(os.path.join(PROJECT_ROOT, "Basic_Functions"))

try:
    import alerter
except ImportError:
    class _Fake:
        @staticmethod
        def trigger_alert(a, b, c, d):
            print("[ALERT]", a, "|", c)
    alerter = _Fake()

MIN_EVENTS = 10
MIN_DURATION = 90
JITTER_TOLERANCE = 0.15
CONSISTENCY_THRESHOLD = 0.80
MAX_INTERVAL = 600
MIN_INTERVAL = 2.0

MIN_TOTAL_BYTES = 15000
MIN_OUT_RATIO = 1.5

CLEANUP_INTERVAL = 180
FLOW_TIMEOUT = 1200
ALERT_COOLDOWN = 3600

COMMON_PORTS = {80, 443, 8080, 53, 123}
BROADCAST_IPS = {"255.255.255.255"}

COMMON_DOMAINS = {
    "google", "microsoft", "cloudflare", "amazonaws",
    "apple", "azure", "facebook", "akamai",
    "openai", "chat.openai", "windowsupdate"
}

KNOWN_SAAS_NETS = (
    "172.64.", "104.16.", "104.17.", "34.", "35.", "20."
)

flow_lock = threading.Lock()

ip_flows = defaultdict(lambda: {
    "times": deque(maxlen=50),
    "sizes": deque(maxlen=50),
    "out_bytes": 0,
    "in_bytes": 0,
    "start": None,
    "last_seen": None
})

dns_flows = defaultdict(lambda: {
    "times": deque(maxlen=50),
    "domains": set(),
    "start": None,
    "last_seen": None
})

alerted_flows = {}
last_cleanup = time.time()

def ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def extract_base_domain(domain):
    parts = domain.lower().split(".")
    if len(parts) >= 3 and len(parts[-1]) <= 3:
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain.lower()

def is_allowlisted_domain(domain):
    d = domain.lower()
    return any(x in d for x in COMMON_DOMAINS)

def is_known_saas_ip(ip):
    return any(ip.startswith(p) for p in KNOWN_SAAS_NETS)

def is_local_traffic(ip):
    return ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.")

def analyze_rhythm(times):
    if len(times) < MIN_EVENTS:
        return False, 0.0

    intervals = []
    for i in range(1, len(times)):
        diff = times[i] - times[i - 1]
        if MIN_INTERVAL <= diff <= MAX_INTERVAL:
            intervals.append(diff)

    if len(intervals) < MIN_EVENTS - 1:
        return False, 0.0

    rounded = [round(i, 1) for i in intervals]
    try:
        beat = mode(rounded)
    except:
        return False, 0.0

    margin = beat * JITTER_TOLERANCE
    matches = sum(1 for i in intervals if abs(i - beat) <= margin)
    consistency = matches / len(intervals)

    if consistency >= CONSISTENCY_THRESHOLD:
        return True, consistency

    return False, 0.0

def cleanup_flows():
    global last_cleanup
    now = time.time()
    if now - last_cleanup < CLEANUP_INTERVAL:
        return

    with flow_lock:
        cutoff = now - FLOW_TIMEOUT
        for k in list(ip_flows):
            if ip_flows[k]["last_seen"] < cutoff:
                del ip_flows[k]

        for k in list(dns_flows):
            if dns_flows[k]["last_seen"] < cutoff:
                del dns_flows[k]

        for k in list(alerted_flows):
            if alerted_flows[k] < now - ALERT_COOLDOWN:
                del alerted_flows[k]

    last_cleanup = now

def detect_dns_beaconing(pkt):
    if not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR) or pkt[DNS].qr != 0:
        return

    try:
        qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
    except:
        return

    if is_allowlisted_domain(qname):
        return

    src = pkt[IP].src if pkt.haslayer(IP) else None
    if not src:
        return

    base = extract_base_domain(qname)
    now = time.time()
    key = (src, base)

    with flow_lock:
        flow = dns_flows[key]
        if not flow["start"]:
            flow["start"] = now
        flow["last_seen"] = now
        flow["times"].append(now)
        flow["domains"].add(qname)

        if len(flow["times"]) < MIN_EVENTS:
            return
        if len(flow["domains"]) < MIN_EVENTS:
            return
        if now - flow["start"] < MIN_DURATION:
            return

        is_bot, conf = analyze_rhythm(list(flow["times"]))
        if is_bot and key not in alerted_flows:
            alerter.trigger_alert(
                "C2_DNS_Beaconing",
                ts(),
                f"Host {src}",
                {"Domain": base, "Confidence": f"{conf:.2f}"}
            )
            alerted_flows[key] = now

def detect_ip_beaconing(pkt):
    if not pkt.haslayer(IP):
        return

    ip = pkt[IP]
    if ip.dst in BROADCAST_IPS:
        return
    if is_local_traffic(ip.dst):
        return
    if is_known_saas_ip(ip.dst):
        return

    port = None
    if pkt.haslayer(TCP):
        port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        port = pkt[UDP].dport
    else:
        return

    if port in COMMON_PORTS:
        return

    now = time.time()
    key = (ip.src, ip.dst, port)

    with flow_lock:
        flow = ip_flows[key]
        if not flow["start"]:
            flow["start"] = now
        flow["last_seen"] = now

        pkt_len = len(pkt)
        flow["times"].append(now)
        flow["sizes"].append(pkt_len)

        if pkt.haslayer(TCP) and pkt[TCP].sport == port:
            flow["in_bytes"] += pkt_len
        else:
            flow["out_bytes"] += pkt_len

        if len(flow["times"]) < MIN_EVENTS:
            return
        if now - flow["start"] < MIN_DURATION:
            return

        total_bytes = flow["out_bytes"] + flow["in_bytes"]
        if total_bytes < MIN_TOTAL_BYTES:
            return

        if flow["in_bytes"] == 0:
            return

        out_ratio = flow["out_bytes"] / flow["in_bytes"]
        if out_ratio < MIN_OUT_RATIO:
            return

        is_bot, conf = analyze_rhythm(list(flow["times"]))
        if is_bot and key not in alerted_flows:
            activity = "Exfiltration" if out_ratio > 3 else "Remote Control"
            alerter.trigger_alert(
                "C2_IP_Beaconing",
                ts(),
                f"Host {ip.src}",
                {
                    "Target": f"{ip.dst}:{port}",
                    "Likely_Activity": activity,
                    "Out_In_Ratio": f"{out_ratio:.2f}",
                    "Confidence": f"{conf:.2f}"
                }
            )
            alerted_flows[key] = now

def process_packet(pkt):
    cleanup_flows()
    try:
        detect_dns_beaconing(pkt)
    except:
        pass
    try:
        detect_ip_beaconing(pkt)
    except:
        pass
