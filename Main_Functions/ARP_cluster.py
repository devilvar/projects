#!/usr/bin/env python3
from scapy.all import sniff, ARP, Ether, srp, BOOTP, DHCP
import threading
import time
import os
import sys
import json
import subprocess
import joblib
import pandas as pd
import logging
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

STATIC_DIR = os.path.join(PROJECT_ROOT, "Basic_data", "JSON")
STATIC_FILE = os.path.join(STATIC_DIR, "Static.json")

LOG_DIR = os.path.join(PROJECT_ROOT, "Basic_data", "logs")
DEVICE_LOG_FILE = os.path.join(LOG_DIR, "device_logs.json")
SYSTEM_LOG_FILE = os.path.join(LOG_DIR, "arp_detector.log")

MODEL_DIR = os.path.join(PROJECT_ROOT, "Model_ARP_Flood")
ARP_MODEL_PATH = os.path.join(MODEL_DIR, "model_arp.pkl")
ARP_SCALER_PATH = os.path.join(MODEL_DIR, "scaler_arp.pkl")
ARP_ENCODER_PATH = os.path.join(MODEL_DIR, "encoder_arp.pkl")
ARP_FEATURE_ORDER_PATH = os.path.join(MODEL_DIR, "feature_order_arp.json")

os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

sys.path.append(os.path.join(PROJECT_ROOT, "Basic_Functions"))
try:
    import alerter
except Exception:
    class _Fake:
        @staticmethod
        def trigger_alert(attack_type, timestamp, source_info, details_dict):
            print(f"[ALERT] {attack_type} | {timestamp} | {source_info} | {details_dict}")
    alerter = _Fake()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(SYSTEM_LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ],
)

def now() -> float:
    return time.time()

def ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def nmac(mac: str | None) -> str | None:
    return mac.lower() if mac else None

def get_gateway_ip() -> str:
    try:
        out = subprocess.check_output("ip route", shell=True).decode()
        for line in out.splitlines():
            if line.startswith("default"):
                parts = line.split()
                if len(parts) >= 3:
                    return parts[2]
    except Exception:
        pass
    return "192.168.1.1"

ROUTER_IP = get_gateway_ip()

device_history = {}

def load_device_logs() -> None:
    global device_history
    if not os.path.exists(DEVICE_LOG_FILE):
        return
    try:
        with open(DEVICE_LOG_FILE, "r") as f:
            data = json.load(f)
        for entry in data:
            mac = nmac(entry.get("mac"))
            if mac:
                device_history[mac] = entry
    except Exception as e:
        logging.error(f"Failed to load device logs: {e}")

def save_device_logs() -> None:
    try:
        entries = list(device_history.values())
        with open(DEVICE_LOG_FILE, "w") as f:
            json.dump(entries, f, indent=4)
    except Exception as e:
        logging.error(f"Failed to save device logs: {e}")

def update_device_history(ip: str, mac: str) -> None:
    mac_norm = nmac(mac)
    if not mac_norm:
        return
    t = ts()
    if mac_norm not in device_history:
        device_history[mac_norm] = {
            "mac": mac_norm,
            "last_ip": ip,
            "first_seen": t,
            "last_seen": t,
        }
    else:
        device_history[mac_norm]["last_seen"] = t
        device_history[mac_norm]["last_ip"] = ip

ALLOWED_MACS: set[str] = set()

def load_static() -> dict:
    global ALLOWED_MACS
    if not os.path.exists(STATIC_FILE):
        ALLOWED_MACS = set()
        return {"allowed_devices": []}
    try:
        with open(STATIC_FILE, "r") as f:
            data = json.load(f)
        devs = []
        for d in data.get("allowed_devices", []):
            mac = nmac(d.get("mac"))
            if mac:
                devs.append({"ip": d.get("ip"), "mac": mac})
        ALLOWED_MACS = set(d["mac"] for d in devs)
        return {"allowed_devices": devs}
    except Exception as e:
        logging.error(f"Error loading Static.json: {e}")
        ALLOWED_MACS = set()
        return {"allowed_devices": []}

def save_static(data: dict) -> None:
    global ALLOWED_MACS
    try:
        devs = []
        for d in data.get("allowed_devices", []):
            mac = nmac(d.get("mac"))
            if mac:
                devs.append({"ip": d.get("ip"), "mac": mac})
        out = {"allowed_devices": devs}
        with open(STATIC_FILE, "w") as f:
            json.dump(out, f, indent=2)
        ALLOWED_MACS = set(d["mac"] for d in devs)
    except Exception as e:
        logging.error(f"Error saving Static.json: {e}")

def initial_scan() -> None:
    data = load_static()
    # We populate the table but don't skip the scan if we want to be sure
    # However, to avoid duplicate code, we can just let the periodic scanner handle it
    # But usually, initial scan populates the Whitelist (Static.json).
    if data.get("allowed_devices"):
        logging.info(f"Loaded {len(data['allowed_devices'])} trusted devices from Static.json")
        # Populate arp_table from static list immediately
        with lock:
            for d in data['allowed_devices']:
                arp_table[d['ip']] = d['mac']
                arp_seen[d['ip']] = now()
    
    # We will let the periodic scanner handle the actual network mapping to keep logic simple

def new_device_seen(ip: str, mac: str) -> None:
    mac_norm = nmac(mac)
    if not mac_norm:
        return
    if mac_norm in ALLOWED_MACS:
        return
    logging.info(f"New device observed: {ip} ({mac_norm})")

INACTIVITY_TIMEOUT = 60
REQUEST_TIMEOUT = 5
PROBE_TIMEOUT = 1
FLOOD_WINDOW = 10
SCAN_INTERVAL = 30 # Scan every 30 seconds

arp_table: dict[str, str] = {}
arp_seen: dict[str, float] = {}
req_map: dict[tuple[str, str], float] = {}
window_pkts = []
garp_history: dict[str, list[tuple[float, str]]] = {}

lock = threading.Lock()

def probe(ip: str, mac: str) -> bool:
    retries = 3
    for attempt in range(retries):
        try:
            pkt_unicast = Ether(dst=mac) / ARP(op=1, pdst=ip, hwdst=mac)
            ans, _ = srp(pkt_unicast, timeout=PROBE_TIMEOUT, verbose=0, iface="eth0")
            if len(ans) > 0:
                return True
            pkt_broadcast = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=ip)
            ans, _ = srp(pkt_broadcast, timeout=PROBE_TIMEOUT, verbose=0, iface="eth0")
            for _, r in ans:
                if nmac(r.hwsrc) == nmac(mac):
                    return True
        except Exception:
            pass
    return False

# --- ACTIVE SCAN FUNCTION ---
def active_map_scan():
    """Scans the entire subnet to update the device list."""
    prefix = ".".join(ROUTER_IP.split(".")[:-1]) + ".0/24"
    try:
        # logging.info("Running periodic network scan...") 
        # Commented out logging to avoid spamming the console every 30s
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=prefix)
        ans, _ = srp(pkt, timeout=2, verbose=0, iface="eth0")
        
        count = 0
        with lock:
            for _, r in ans:
                mac = nmac(r.hwsrc)
                ip = r.psrc
                if not mac: continue
                
                # Update tables
                arp_table[ip] = mac
                arp_seen[ip] = now()
                update_device_history(ip, mac)
                count += 1
        
        save_device_logs()
        # logging.info(f"Scan complete. {count} devices active.")
        
    except Exception as e:
        logging.error(f"Periodic scan failed: {e}")

def extract_features(pkts: list) -> dict:
    if not pkts:
        keys = ["arp_count","unique_senders","unique_targets","broadcast_count","broadcast_ratio","mac_conflict_count","mac_conflict_ratio","mean_interval","variance_interval","interval_count"]
        return {k: 0.0 for k in keys}
    ts_list = sorted(float(p.time) for p in pkts)
    intervals = [ts_list[i] - ts_list[i - 1] for i in range(1, len(ts_list))]
    senders = set()
    targets = set()
    broadcast_count = 0
    mac_conflicts = 0
    ip_mac_map: dict[str, str] = {}
    for p in pkts:
        a = p[ARP]
        s_ip = a.psrc
        s_mac = nmac(a.hwsrc)
        d_mac = nmac(a.hwdst)
        t_ip = a.pdst
        senders.add(s_ip)
        targets.add(t_ip)
        if d_mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            broadcast_count += 1
        if s_ip not in ip_mac_map:
            ip_mac_map[s_ip] = s_mac
        elif ip_mac_map[s_ip] != s_mac:
            mac_conflicts += 1
    def mean(v: list[float]) -> float: return sum(v) / len(v) if v else 0.0
    def var(v: list[float]) -> float:
        if not v: return 0.0
        m = mean(v)
        return sum((x - m) ** 2 for x in v) / len(v)
    total = len(pkts)
    return {
        "arp_count": float(total),
        "unique_senders": float(len(senders)),
        "unique_targets": float(len(targets)),
        "broadcast_count": float(broadcast_count),
        "broadcast_ratio": float(broadcast_count) / float(total) if total else 0.0,
        "mac_conflict_count": float(mac_conflicts),
        "mac_conflict_ratio": float(mac_conflicts) / float(total) if total else 0.0,
        "mean_interval": float(mean(intervals)),
        "variance_interval": float(var(intervals)),
        "interval_count": float(len(intervals)),
    }

MODEL = None
SCALER = None
ENCODER = None
FEATURE_ORDER: list[str] | None = None

def flood_thread() -> None:
    global MODEL, SCALER, ENCODER, FEATURE_ORDER
    if not os.path.exists(ARP_MODEL_PATH):
        logging.warning("ARP ML model not found; flood detection disabled.")
        return
    try:
        MODEL = joblib.load(ARP_MODEL_PATH)
        if os.path.exists(ARP_SCALER_PATH): SCALER = joblib.load(ARP_SCALER_PATH)
        if os.path.exists(ARP_ENCODER_PATH): ENCODER = joblib.load(ARP_ENCODER_PATH)
        if os.path.exists(ARP_FEATURE_ORDER_PATH):
            with open(ARP_FEATURE_ORDER_PATH, "r") as f: FEATURE_ORDER = json.load(f)
        logging.info("ARP Flood ML model and artifacts loaded.")
    except Exception as e:
        logging.error(f"Failed loading ARP ML artifacts: {e}")
        MODEL = None
        return
    while True:
        time.sleep(FLOOD_WINDOW)
        with lock:
            pk = list(window_pkts)
            window_pkts.clear()
        if not pk or MODEL is None or FEATURE_ORDER is None: continue
        try:
            f = extract_features(pk)
            vec = [f[name] for name in FEATURE_ORDER]
            df = pd.DataFrame([vec], columns=FEATURE_ORDER)
            X = df.values
            if SCALER is not None:
                try: X = SCALER.transform(X)
                except Exception as e: logging.error(f"Scaler error: {e}")
            preds = MODEL.predict(X)
            raw_label = preds[0]
            label = ENCODER.inverse_transform([raw_label])[0] if ENCODER is not None else str(raw_label)
            if str(label).lower() != "normal":
                logging.warning(f"ML detected ARP flood: {label}")
                alerter.trigger_alert("ARP_Flood_ML", ts(), "Heuristic ARP flood detection", {"label": str(label), "arp_count": f["arp_count"]})
        except Exception as e:
            logging.error(f"Error in flood_thread: {e}")

def clean_thread() -> None:
    while True:
        time.sleep(max(1, INACTIVITY_TIMEOUT // 2))
        cur = now()
        with lock:
            for ip, last_seen in list(arp_seen.items()):
                if cur - last_seen > INACTIVITY_TIMEOUT:
                    arp_seen.pop(ip, None)
                    arp_table.pop(ip, None)
            for ip, entries in list(garp_history.items()):
                garp_history[ip] = [(t, m) for (t, m) in entries if cur - t <= FLOOD_WINDOW]
                if not garp_history[ip]: garp_history.pop(ip, None)
        save_device_logs()

# --- NEW PERIODIC SCAN THREAD ---
def periodic_scan_thread() -> None:
    """Runs the network scan every 30 seconds."""
    while True:
        active_map_scan()
        time.sleep(SCAN_INTERVAL)

def pkt_handler(p) -> None:
    if p.haslayer(DHCP):
        try:
            opts = p[DHCP].options
            msg_type = None
            for o in opts:
                if isinstance(o, tuple) and o[0] == "message-type":
                    msg_type = o[1]
                    break
            if msg_type == 5:
                boot = p[BOOTP]
                ip = boot.yiaddr
                mac = nmac(":".join("%02x" % b for b in boot.chaddr[:6]))
                with lock:
                    arp_table[ip] = mac
                    arp_seen[ip] = now()
                    update_device_history(ip, mac)
        except Exception: pass
        return
    if not p.haslayer(ARP): return
    a = p[ARP]
    with lock: window_pkts.append(p)
    s_ip = a.psrc
    s_mac = nmac(a.hwsrc)
    t_ip = a.pdst
    op = int(getattr(a, "op", 0))
    cur = now()
    with lock:
        update_device_history(s_ip, s_mac)
        if op == 1:
            req_map[(s_ip, t_ip)] = cur
            if s_ip not in arp_table:
                arp_table[s_ip] = s_mac
                arp_seen[s_ip] = cur
                new_device_seen(s_ip, s_mac)
            else:
                arp_seen[s_ip] = cur
            return
        if op == 2:
            known_mac = arp_table.get(s_ip)
            key = (t_ip, s_ip)
            requested = key in req_map and (cur - req_map[key] < REQUEST_TIMEOUT)
            if not requested:
                if known_mac is None:
                    if s_ip == ROUTER_IP: pass # Dont trust blind router updates
                    else:
                        arp_table[s_ip] = s_mac
                        arp_seen[s_ip] = cur
                        new_device_seen(s_ip, s_mac)
                    return
                if known_mac == s_mac:
                    arp_seen[s_ip] = cur
                    update_device_history(s_ip, s_mac)
                    return
                garp_history.setdefault(s_ip, []).append((cur, s_mac))
                garp_history[s_ip] = [(t, m) for (t, m) in garp_history[s_ip] if cur - t <= FLOOD_WINDOW]
            if known_mac and known_mac != s_mac:
                old_alive = probe(s_ip, known_mac)
                if not old_alive:
                    logging.info(f"IP {s_ip} changed {known_mac} -> {s_mac} (old device silent)")
                    arp_table[s_ip] = s_mac
                    arp_seen[s_ip] = cur
                    new_device_seen(s_ip, s_mac)
                else:
                    logging.critical(f"Confirmed ARP spoofing: {s_ip} legit {known_mac}, attacker {s_mac}")
                    alerter.trigger_alert("ARP_Spoofing_Confirmed", ts(), f"Attacker MAC {s_mac}", {"target_ip": s_ip, "legit_mac": known_mac, "attacker_mac": s_mac})
                    return
            if known_mac == s_mac:
                arp_seen[s_ip] = cur

if __name__ == "__main__":
    print(f"Starting ARP Detector; gateway detected as {ROUTER_IP}")
    print(f"Device history: {DEVICE_LOG_FILE}")
    print(f"System log:     {SYSTEM_LOG_FILE}")
    load_device_logs()
    initial_scan()
    
    # Start all threads
    t1 = threading.Thread(target=clean_thread, daemon=True)
    t1.start()
    t2 = threading.Thread(target=flood_thread, daemon=True)
    t2.start()
    t3 = threading.Thread(target=periodic_scan_thread, daemon=True) # New Scan Thread
    t3.start()
    
    try:
        sniff(filter="arp or (udp and (port 67 or 68))", prn=pkt_handler, store=False)
    except KeyboardInterrupt:
        save_device_logs()
        print("\nStopped by user.")
    except PermissionError:
        print("\nPermission error: run this script as root (sudo).")
