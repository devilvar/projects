#!/usr/bin/env python3
"""
Unified Policy Engine (FINAL)
- MAC-based user detection
- Restricted website detection
- Clears users.json on each run
- Alerts ONLY once per new MAC
- Designed for subCluster2 packet sharing
- Standalone sniffing only for testing
"""

import os
import sys
import json
import time
from scapy.layers.l2 import Ether
from scapy.layers.inet import TCP
from scapy.layers.dns import DNS

# ================= PATH SETUP =================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJECT_ROOT = BASE_DIR
JSON_DIR = os.path.join(PROJECT_ROOT, "Basic_data", "JSON")

BASIC_FUNCTIONS_DIR = os.path.join(PROJECT_ROOT, "Basic_Functions")
sys.path.insert(0, BASIC_FUNCTIONS_DIR)

import alerter

# ================= FILE PATHS =================

USERS_FILE = os.path.join(JSON_DIR, "users.json")
TRUSTED_FILE = os.path.join(JSON_DIR, "Trusted_Users.json")
RESTRICT_FILE = os.path.join(JSON_DIR, "Restrict_web.json")

os.makedirs(JSON_DIR, exist_ok=True)

# ================= FILE HELPERS =================

def _load_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r") as f:
            return json.load(f)
    except:
        return default

def _save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)

# ================= SESSION INIT =================

def reset_users_file():
    """
    Clears users.json at every fresh run
    """
    _save_json(USERS_FILE, {})
    print("[IAM] users.json reset for new session")

reset_users_file()

# ================= CORE ENGINE =================

def process_packet(pkt):
    """
    Called by subCluster2 for every packet
    """

    if not pkt.haslayer(Ether):
        return

    src_mac = pkt[Ether].src.lower()
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    users = _load_json(USERS_FILE, {})
    trusted = _load_json(TRUSTED_FILE, [])
    restricted = _load_json(RESTRICT_FILE, [])

    # -------- NEW USER DETECTION --------

    if src_mac not in users:
        users[src_mac] = {
            "first_seen": timestamp,
            "last_seen": timestamp
        }
        _save_json(USERS_FILE, users)

        # Alert ONLY ONCE per MAC
        if src_mac not in trusted:
            alerter.trigger_alert(
                attack_type="Unknown_Device_Detected",
                timestamp=timestamp,
                source_info=f"MAC: {src_mac}"
            )
        return  # Do not reprocess this packet

    # Update last_seen silently
    users[src_mac]["last_seen"] = timestamp
    _save_json(USERS_FILE, users)

    # -------- RESTRICTED WEBSITE --------

    # Trusted users bypass restrictions
    if src_mac in trusted or not restricted:
        return

    # DNS-based detection
    if pkt.haslayer(DNS) and pkt[DNS].qd:
        try:
            query = pkt[DNS].qd.qname.decode(errors="ignore").lower()
            for domain in restricted:
                if domain.lower() in query:
                    alerter.trigger_alert(
                        attack_type="Restricted_Web_Access",
                        timestamp=timestamp,
                        source_info=f"MAC: {src_mac}",
                        details_dict={"Domain": query}
                    )
                    return
        except:
            pass

    # HTTP-based detection
    if pkt.haslayer(TCP) and pkt[TCP].dport == 80:
        try:
            payload = bytes(pkt[TCP].payload)
            for domain in restricted:
                if domain.encode() in payload:
                    alerter.trigger_alert(
                        attack_type="Restricted_Web_Access",
                        timestamp=timestamp,
                        source_info=f"MAC: {src_mac}",
                        details_dict={"Domain": domain}
                    )
                    return
        except:
            pass

# ================= TEST MODE =================

if __name__ == "__main__":
    from scapy.all import sniff

    print("[TEST MODE] Unified Policy Engine running")
    sniff(prn=process_packet, store=False)
