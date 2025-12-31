#!/usr/bin/env python3
import time
import threading
import sys
import os
import ipaddress
import subprocess
from collections import defaultdict
from datetime import datetime
from scapy.all import DNS, DNSRR, IP, Ether, sniff

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

DNS_QUERY_WINDOW = 5
DNS_RESPONSE_WINDOW = 3
DNS_POISON_WINDOW = 3
IP_MAC_WINDOW = 30

dns_queries = {}
dns_responses = defaultdict(list)
dns_answers = defaultdict(list)
ip_mac_map = {}

dns_lock = threading.Lock()
ip_lock = threading.Lock()

TRUSTED_DNS_SERVERS = set()

def get_default_gateway():
    try:
        output = subprocess.check_output(["ip", "route"], stderr=subprocess.DEVNULL).decode()
        for line in output.splitlines():
            if line.startswith("default"):
                return line.split()[2]
    except:
        return None

gw = get_default_gateway()
if gw:
    TRUSTED_DNS_SERVERS.add(gw)

def ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def is_private_ip(ip_str):
    try:
        return ipaddress.ip_address(ip_str).is_private
    except:
        return False

def extract_dns_ips(dns):
    ips = []
    if dns.an:
        for i in range(dns.ancount):
            rr = dns.an[i]
            if isinstance(rr, DNSRR) and rr.type == 1:
                ips.append(rr.rdata)
    return ips

def detect_dns_spoofing_and_poisoning(pkt):
    if not pkt.haslayer(DNS) or not pkt.haslayer(IP):
        return

    ip = pkt[IP]
    dns = pkt[DNS]
    now = time.time()

    with dns_lock:
        if dns.qr == 0 and dns.qd:
            dns_queries[(ip.src, dns.qd.qname, dns.id)] = now
            for k in list(dns_queries):
                if now - dns_queries[k] > DNS_QUERY_WINDOW:
                    del dns_queries[k]
            return

        if dns.qr != 1 or not dns.qd:
            return

        qname = dns.qd.qname
        qname_str = qname.decode(errors="ignore").rstrip(".")
        src_ip = ip.src
        dst_ip = ip.dst
        txid = dns.id

        valid_query = (
            (dst_ip, qname, txid) in dns_queries and
            now - dns_queries[(dst_ip, qname, txid)] <= DNS_QUERY_WINDOW
        )

        if not valid_query and src_ip not in TRUSTED_DNS_SERVERS:
            alerter.trigger_alert(
                "DNS_Spoofing_Unsolicited",
                ts(),
                f"Fake DNS Server: {src_ip}",
                {"Query": qname_str}
            )

        resp_key = (dst_ip, qname)
        dns_responses[resp_key].append((src_ip, now))
        dns_responses[resp_key] = [r for r in dns_responses[resp_key] if now - r[1] <= DNS_RESPONSE_WINDOW]

        responders = set(r[0] for r in dns_responses[resp_key])
        if len(responders) > 1 and not responders.issubset(TRUSTED_DNS_SERVERS):
            alerter.trigger_alert(
                "DNS_Spoofing_Race",
                ts(),
                f"Multiple DNS responders: {list(responders)}",
                {"Query": qname_str}
            )
            del dns_responses[resp_key]

        answer_ips = extract_dns_ips(dns)

        for rip in answer_ips:
            if is_private_ip(rip):
                if not (qname_str.endswith(".local") or qname_str.endswith(".lan") or "home" in qname_str):
                    alerter.trigger_alert(
                        "DNS_Cache_Poisoning",
                        ts(),
                        f"Spoofer: {src_ip}",
                        {"Domain": qname_str, "Fake_IP": rip}
                    )

        if answer_ips:
            key = (dst_ip, qname)
            dns_answers[key].append(
                {"ips": answer_ips, "src": src_ip, "time": now, "unsolicited": not valid_query}
            )

            dns_answers[key] = [
                a for a in dns_answers[key]
                if now - a["time"] <= DNS_POISON_WINDOW
            ]

            unique_ips = set()
            unique_sources = set()
            unsolicited = False

            for e in dns_answers[key]:
                unique_ips.update(e["ips"])
                unique_sources.add(e["src"])
                if e["unsolicited"]:
                    unsolicited = True

            if (
                len(unique_ips) > 1 and
                len(unique_sources) > 1 and
                unsolicited and
                not unique_sources.issubset(TRUSTED_DNS_SERVERS)
            ):
                alerter.trigger_alert(
                    "DNS_Cache_Poisoning_Attempt",
                    ts(),
                    "Conflicting unsolicited DNS answers",
                    {
                        "Domain": qname_str,
                        "Answer_IPs": list(unique_ips),
                        "Sources": list(unique_sources)
                    }
                )
                del dns_answers[key]

def detect_ip_spoofing(pkt):
    if not pkt.haslayer(IP) or not pkt.haslayer(Ether):
        return

    ip = pkt[IP]
    eth = pkt[Ether]
    now = time.time()

    src_ip = ip.src
    src_mac = eth.src

    if src_ip.startswith("0.") or src_ip.startswith("255.") or src_ip == "255.255.255.255":
        return

    with ip_lock:
        if src_ip in ip_mac_map:
            old_mac, old_time = ip_mac_map[src_ip]
            if src_mac != old_mac and now - old_time <= IP_MAC_WINDOW:
                alerter.trigger_alert(
                    "IP_Spoofing_MAC_Mismatch",
                    ts(),
                    f"MAC change detected for {src_ip}",
                    {"Old_MAC": old_mac, "New_MAC": src_mac}
                )

        ip_mac_map[src_ip] = (src_mac, now)

def process_packet(pkt):
    try:
        detect_dns_spoofing_and_poisoning(pkt)
    except:
        pass
    try:
        detect_ip_spoofing(pkt)
    except:
        pass

if __name__ == "__main__":
    print("DNS Spoofing, DNS Cache Poisoning & IP Spoofing Module Running")
    try:
        sniff(iface="eth0", prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("Stopped")
