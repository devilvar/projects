#!/usr/bin/env python3
import time
import sys
import os
import ipaddress
import socket
from datetime import datetime
from scapy.all import IP, TCP, UDP

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

# ================= PI IP DETECTION =================

def get_pi_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None

PI_IP = get_pi_ip()

# ================= CONFIG =================

INSECURE_PROTOCOLS = {
    23:  ("Telnet", "Clear-text remote login"),
    21:  ("FTP", "Clear-text file transfer"),
    80:  ("HTTP", "Unencrypted web traffic"),
    69:  ("TFTP", "Unauthenticated file transfer"),
    161: ("SNMP", "Weak community strings"),
}

TRUSTED_EXTERNAL_NETWORKS = [
    "23.0.0.0/8",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "151.101.0.0/16",
    "199.232.0.0/16",
    "13.64.0.0/11",
    "20.0.0.0/8",
    "40.64.0.0/10",
    "52.96.0.0/12",
    "34.64.0.0/10",
    "35.184.0.0/13",
    "142.250.0.0/15",
    "13.32.0.0/11",
    "13.224.0.0/14",
    "52.84.0.0/14",
    "1.1.1.1/32",
    "8.8.8.8/32",
    "9.9.9.9/32",
]

TRUSTED_NETS = [ipaddress.ip_network(n) for n in TRUSTED_EXTERNAL_NETWORKS]

ALERT_COOLDOWN = 120
last_alert = {}

def ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def is_private(ip):
    return ipaddress.ip_address(ip).is_private

def is_trusted_external(ip):
    try:
        addr = ipaddress.ip_address(ip)
        for net in TRUSTED_NETS:
            if addr in net:
                return True
    except Exception:
        pass
    return False

def detect_insecure_protocols(pkt):
    if not pkt.haslayer(IP):
        return

    ip = pkt[IP]
    src_ip = ip.src
    dst_ip = ip.dst
    now = time.time()

    proto = None
    port = None

    if pkt.haslayer(TCP):
        proto = "TCP"
        port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        proto = "UDP"
        port = pkt[UDP].dport
    else:
        return

    if port not in INSECURE_PROTOCOLS:
        return

    protocol_name, risk = INSECURE_PROTOCOLS[port]

    internal_to_internal = is_private(src_ip) and is_private(dst_ip)
    internal_to_external = is_private(src_ip) and not is_private(dst_ip)
    external_to_internal = not is_private(src_ip) and is_private(dst_ip)

    trusted_external_flow = (
        is_trusted_external(src_ip) or
        is_trusted_external(dst_ip)
    )

    # ================= HTTP PI EXCLUSION =================
    if protocol_name == "HTTP":
        if PI_IP and (src_ip == PI_IP or dst_ip == PI_IP):
            return
        if trusted_external_flow:
            return
    else:
        if trusted_external_flow:
            return

    alert_key = (src_ip, dst_ip, protocol_name)
    if alert_key in last_alert:
        if now - last_alert[alert_key] < ALERT_COOLDOWN:
            return

    alerter.trigger_alert(
        attack_type="Insecure_Protocol_Usage",
        timestamp=ts(),
        source_info=f"{src_ip} → {dst_ip}",
        details_dict={
            "Protocol": protocol_name,
            "Transport": proto,
            "Port": port,
            "Risk": risk,
            "Flow_Type": (
                "Internal→Internal" if internal_to_internal else
                "Internal→External" if internal_to_external else
                "External→Internal"
            )
        }
    )

    last_alert[alert_key] = now

def process_packet(pkt):
    try:
        detect_insecure_protocols(pkt)
    except Exception:
        pass

if __name__ == "__main__":
    print("Policy Violation Detection Running")
