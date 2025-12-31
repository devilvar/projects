#!/usr/bin/env python3
import sys
import os
import time
import subprocess
from collections import defaultdict
from scapy.all import DHCP, BOOTP, IP, Ether, sniff
from datetime import datetime

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

def get_default_gateway():
    try:
        output = subprocess.check_output(
            ["ip", "route"], stderr=subprocess.DEVNULL
        ).decode()
        for line in output.splitlines():
            if line.strip().startswith("default"):
                parts = line.split()
                if len(parts) > 2:
                    return parts[2]
    except Exception:
        pass
    return None

STARVATION_THRESHOLD = 20
WINDOW = 10

ROUTER_IP = get_default_gateway()
ROGUE_DETECTION_ENABLED = True

if not ROUTER_IP:
    print("WARNING: Default gateway not detected. Rogue DHCP detection disabled.")
    ROGUE_DETECTION_ENABLED = False
else:
    print("Trusted DHCP Server detected:", ROUTER_IP)

discover_history = []
last_cleanup = time.time()

def ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def detect_dhcp_attacks(pkt):
    global discover_history, last_cleanup

    if not pkt.haslayer(DHCP) or not pkt.haslayer(BOOTP):
        return

    msg_type = None
    server_id = None

    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple):
            if opt[0] == "message-type":
                msg_type = opt[1]
            elif opt[0] == "server_id":
                server_id = opt[1]

    if msg_type is None:
        return

    now = time.time()

    # -------------------------------------------------
    # 1. DHCP STARVATION (DISCOVER FLOOD)
    # -------------------------------------------------
    if msg_type == 1:
        src_mac = pkt[Ether].src if pkt.haslayer(Ether) else "Unknown"
        discover_history.append((now, src_mac))

        if now - last_cleanup > 1.0:
            discover_history = [
                x for x in discover_history if now - x[0] <= WINDOW
            ]
            last_cleanup = now

        total_discovers = len(discover_history)

        if total_discovers > STARVATION_THRESHOLD:
            unique_macs = set(mac for _, mac in discover_history)
            unique_count = len(unique_macs)

            if unique_count > (STARVATION_THRESHOLD * 0.5):
                alerter.trigger_alert(
                    "DHCP_Starvation",
                    ts(),
                    "Multiple Random MACs",
                    {
                        "Rate": f"{total_discovers/WINDOW:.1f} req/sec",
                        "Unique_MACs": unique_count,
                        "Window": WINDOW
                    }
                )
                discover_history.clear()
            else:
                mac_counts = defaultdict(int)
                for _, mac in discover_history:
                    mac_counts[mac] += 1
                noisy_mac = max(mac_counts, key=mac_counts.get)

                alerter.trigger_alert(
                    "DHCP_Client_Flood",
                    ts(),
                    f"Source MAC: {noisy_mac}",
                    {
                        "Rate": f"{mac_counts[noisy_mac]/WINDOW:.1f} req/sec",
                        "Window": WINDOW
                    }
                )
                discover_history.clear()

    # -------------------------------------------------
    # 2. ROGUE DHCP OFFER DETECTION
    # -------------------------------------------------
    elif msg_type == 2 and ROGUE_DETECTION_ENABLED:
        if not server_id or server_id != ROUTER_IP:
            alerter.trigger_alert(
                "Rogue_DHCP_Server",
                ts(),
                f"Server-ID: {server_id}",
                {
                    "Expected": ROUTER_IP,
                    "Found": server_id,
                    "Type": "Option 54 Missing or Mismatch"
                }
            )
            return

        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            if src_ip != ROUTER_IP:
                alerter.trigger_alert(
                    "Rogue_DHCP_Server",
                    ts(),
                    f"Source IP: {src_ip}",
                    {
                        "Expected": ROUTER_IP,
                        "Found": src_ip,
                        "Type": "IP Header Mismatch"
                    }
                )

    # -------------------------------------------------
    # 3. DHCP ACK SPOOFING DETECTION
    # -------------------------------------------------
    elif msg_type == 5 and ROGUE_DETECTION_ENABLED:
        # Check Option 54 (Server Identifier)
        if not server_id or server_id != ROUTER_IP:
            alerter.trigger_alert(
                "DHCP_ACK_Spoofing",
                ts(),
                f"ACK from Server-ID: {server_id}",
                {
                    "Expected": ROUTER_IP,
                    "Found": server_id,
                    "Violation": "Unauthorized DHCP ACK (Option 54)"
                }
            )
            return

        # Check IP source
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            if src_ip != ROUTER_IP:
                alerter.trigger_alert(
                    "DHCP_ACK_Spoofing",
                    ts(),
                    f"ACK from Source IP: {src_ip}",
                    {
                        "Expected": ROUTER_IP,
                        "Found": src_ip,
                        "Violation": "Unauthorized DHCP ACK (IP Source)"
                    }
                )

if __name__ == "__main__":
    print("DHCP Security Module Running")
    if ROGUE_DETECTION_ENABLED:
        print("Trusted Gateway:", ROUTER_IP)
    sniff(
        iface="eth0",
        filter="udp and (port 67 or 68)",
        prn=detect_dhcp_attacks,
        store=0
    )
