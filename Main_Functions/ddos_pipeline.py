#!/usr/bin/env python3
import os
import sys
import time
import math
import json
from datetime import datetime
from collections import Counter

from scapy.all import sniff, IP, TCP, UDP, ICMP
import pandas as pd
import joblib
import warnings
warnings.filterwarnings("ignore", category=UserWarning)
# PATH SETUP
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
# Model-1 (RF DDoS)
MODEL1_DIR = os.path.join(PROJECT_ROOT, "Model1_ddos")
MODEL1_PATH = os.path.join(MODEL1_DIR, "ddos_detection_model.pkl")
MODEL1_ENCODER_PATH = os.path.join(MODEL1_DIR, "label_encoder.pkl")
MODEL1_FEATURES_PATH = os.path.join(MODEL1_DIR, "feature_order.pkl")
# Model-2 (GB DDoS)
MODEL2_DIR = os.path.join(PROJECT_ROOT, "Model2_ddos")
MODEL2_PATH = os.path.join(MODEL2_DIR, "model2_model.pkl")
MODEL2_SCALER_PATH = os.path.join(MODEL2_DIR, "model2_scaler.pkl")
MODEL2_ENCODER_PATH = os.path.join(MODEL2_DIR, "model2_label_encoder.pkl")
M2_FEAT_PATH = os.path.join(MODEL2_DIR, "feature_order_model2.pkl")
# Model-3 (Teardrop Verification)
MODEL3_DIR = os.path.join(PROJECT_ROOT, "Model3_ddos")
MODEL3_PATH = os.path.join(MODEL3_DIR, "model3_model.pkl")
MODEL3_SCALER_PATH = os.path.join(MODEL3_DIR, "model3_scaler.pkl")
MODEL3_ENCODER_PATH = os.path.join(MODEL3_DIR, "model3_label_encoder.pkl")
MODEL3_FEATURE_PATH = os.path.join(MODEL3_DIR, "feature_order_model3.json")
# Model-4 (Mixed Attack Verification)
MODEL4_DIR = os.path.join(PROJECT_ROOT, "Model4_ddos")
MODEL4_PATH = os.path.join(MODEL4_DIR, "model4_model.pkl")
MODEL4_SCALER_PATH = os.path.join(MODEL4_DIR, "model4_scaler.pkl")
MODEL4_ENCODER_PATH = os.path.join(MODEL4_DIR, "model4_label_encoder.pkl")
MODEL4_FEATURE_PATH = os.path.join(MODEL4_DIR, "feature_order_model4.json")
# Model-6 (Reconnaissance / Port Scan)
MODEL6_DIR = os.path.join(PROJECT_ROOT, "Model_Recon")
M6_PATH = os.path.join(MODEL6_DIR, "model6_recon.pkl")
M6_SCALER_PATH = os.path.join(MODEL6_DIR, "scaler6_recon.pkl")
M6_ENCODER_PATH = os.path.join(MODEL6_DIR, "encoder6_recon.pkl")
M6_FEAT_PATH = os.path.join(MODEL6_DIR, "feature_order6_recon.json")

# Import alerter
sys.path.insert(0, os.path.join(PROJECT_ROOT, "Basic_Functions"))
import alerter  # noqa: E402
# CONFIG
WINDOW = 10
IFACE = "eth0"
# Fallback threshold (kept for Model-3 heuristic fallback only)
TEARDROP_MIN_FRAGMENT_RATIO = 0.3
# UTILS
def calculate_entropy(values):
    """Calculate Shannon entropy with O(n) complexity"""
    if not values:
        return 0.0
    freq = Counter(values)
    total = len(values)
    return -sum((c / total) * math.log2(c / total) for c in freq.values() if c > 0)
# FEATURE EXTRACTOR 1: DDoS (Model 1)
def extract_model1_features(pkt_list):
    features = {
        "pkt_count": len(pkt_list), "byte_count": sum(len(pkt) for pkt in pkt_list),
        "unique_src_ips": 0, "unique_dst_ports": 0, "syn_count": 0, "syn_ack_count": 0,
        "udp_count": 0, "icmp_count": 0, "avg_pkt_size": 0.0, "pps": 0.0, "bps": 0.0,
        "syn_ratio": 0.0, "udp_ratio": 0.0, "src_ip_entropy": 0.0, "icmp_ratio": 0.0,
        "avg_flow_duration": 0.0, "unique_dst_ports_ratio": 0.0, "fragment_count": 0,
        "fragment_ratio": 0.0, "avg_fragment_size": 0.0, "connection_count": 0,
        "request_rate": 0.0, "avg_pkts_per_flow": 0.0, "psh_ack_ratio": 0.0,
    }
    src_ips = []
    dst_ports = set()
    flows = {}
    fragment_byte_count = 0
    http_request_count = 0
    psh_ack_count = 0

    for pkt in pkt_list:
        if not pkt.haslayer(IP): continue
        ip = pkt[IP]
        src_ips.append(ip.src)
        if ip.flags.MF or ip.frag > 0:
            features["fragment_count"] += 1
            fragment_byte_count += len(ip)

        flow_key = None
        if pkt.haslayer(TCP) or pkt.haslayer(UDP):
            protocol = "TCP" if pkt.haslayer(TCP) else "UDP"
            flow_key = (tuple(sorted(((ip.src, pkt.sport), (ip.dst, pkt.dport)))) + (protocol,))
            if flow_key not in flows:
                flows[flow_key] = {"pkt_count": 0, "start_time": pkt.time, "last_time": pkt.time, "has_fin_rst": False}
            flows[flow_key]["pkt_count"] += 1
            flows[flow_key]["last_time"] = pkt.time

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            dst_ports.add(tcp.dport)
            if tcp.flags.S and not tcp.flags.A: features["syn_count"] += 1
            if tcp.flags.S and tcp.flags.A: features["syn_ack_count"] += 1
            if tcp.flags.P and tcp.flags.A: psh_ack_count += 1
            if tcp.dport == 80 and pkt.haslayer("Raw"):
                try:
                    payload = pkt["Raw"].load.decode(errors="ignore").upper()
                    if payload.startswith("GET") or payload.startswith("POST"): http_request_count += 1
                except: pass
            if tcp.flags.F or tcp.flags.R:
                if flow_key: flows[flow_key]["has_fin_rst"] = True
        elif pkt.haslayer(UDP):
            dst_ports.add(pkt[UDP].dport)
            features["udp_count"] += 1
        elif pkt.haslayer(ICMP):
            features["icmp_count"] += 1

    features["unique_src_ips"] = len(set(src_ips))
    features["unique_dst_ports"] = len(dst_ports)

    if features["pkt_count"] > 0:
        features["avg_pkt_size"] = features["byte_count"] / features["pkt_count"]
        features["pps"] = features["pkt_count"] / WINDOW
        features["bps"] = features["byte_count"] / WINDOW
        features["syn_ratio"] = features["syn_count"] / features["pkt_count"]
        features["udp_ratio"] = features["udp_count"] / features["pkt_count"]
        features["icmp_ratio"] = features["icmp_count"] / features["pkt_count"]
        features["src_ip_entropy"] = calculate_entropy(src_ips)
        features["unique_dst_ports_ratio"] = len(dst_ports) / features["pkt_count"]
        features["fragment_ratio"] = features["fragment_count"] / features["pkt_count"]
        features["psh_ack_ratio"] = psh_ack_count / features["pkt_count"]
        if features["fragment_count"] > 0:
            features["avg_fragment_size"] = fragment_byte_count / features["fragment_count"]

    return features
# FEATURE EXTRACTOR 2: Model 2 (Secondary DDoS)
def extract_model2_features(pkt_list):
    extra = {
        "fin_count": 0, "rst_count": 0, "null_flag_count": 0, "xmas_flag_count": 0,
        "ttl_mean": 0.0, "ttl_std": 0.0, "inter_arrival_mean": 0.0, "inter_arrival_std": 0.0,
        "src_port_entropy": 0.0, "incomplete_handshake_ratio": 0.0, "pkt_rate_variation": 0.0,
        "flow_count": 0, "pkt_count": len(pkt_list), "byte_count": sum(len(pkt) for pkt in pkt_list)
    }
    if not pkt_list: return extra

    src_ports = []
    tcp_flows = {}
    ttls = []
    per_second = {}
    arrival_times = []
    last_time = None
    start_ts = pkt_list[0].time

    for pkt in pkt_list:
        sec = int(pkt.time - start_ts)
        per_second[sec] = per_second.get(sec, 0) + 1
        if not pkt.haslayer(IP): continue
        ip = pkt[IP]
        ttls.append(ip.ttl)
        if last_time:
            dt = pkt.time - last_time
            if dt > 0: arrival_times.append(dt)
        last_time = pkt.time

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            src_ports.append(tcp.sport)
            flags = tcp.flags
            if flags.F: extra["fin_count"] += 1
            if flags.R: extra["rst_count"] += 1
            if int(flags) == 0: extra["null_flag_count"] += 1
            if flags.F and flags.P and flags.U: extra["xmas_flag_count"] += 1

            fkey = (ip.src, ip.dst, tcp.sport, tcp.dport)
            if fkey not in tcp_flows: tcp_flows[fkey] = {"syn": False, "fin_rst": False}
            if flags.S and not flags.A: tcp_flows[fkey]["syn"] = True
            if flags.F or flags.R: tcp_flows[fkey]["fin_rst"] = True

    if ttls:
        mean = sum(ttls)/len(ttls)
        var = sum((t - mean)**2 for t in ttls) / len(ttls)
        extra["ttl_mean"] = mean
        extra["ttl_std"] = math.sqrt(var)

    if arrival_times:
        mean = sum(arrival_times)/len(arrival_times)
        var = sum((x - mean)**2 for x in arrival_times) / len(arrival_times)
        extra["inter_arrival_mean"] = mean
        extra["inter_arrival_std"] = math.sqrt(var)

    extra["src_port_entropy"] = calculate_entropy(src_ports)

    if tcp_flows:
        incomplete = sum(1 for f in tcp_flows.values() if f["syn"] and not f["fin_rst"])
        extra["incomplete_handshake_ratio"] = incomplete / len(tcp_flows)
        extra["flow_count"] = len(tcp_flows)

    if per_second:
        vals = list(per_second.values())
        mean = sum(vals)/len(vals)
        var = sum((v - mean)**2 for v in vals) / len(vals)
        extra["pkt_rate_variation"] = math.sqrt(var)

    return extra
# FEATURE EXTRACTOR 3: Model 3 (Teardrop - 13 Features)
def extract_model3_features(pkt_list):
    """Extract the full 13-feature set required for Model-3 (Teardrop ML verification)."""
    
    features = {
        "pkt_count": len(pkt_list),
        "byte_count": sum(len(pkt) for pkt in pkt_list),
        "fragment_count": 0,
        "fragment_ratio": 0.0,
        "avg_fragment_size": 0.0,
        "inter_arrival_mean": 0.0,
        "inter_arrival_std": 0.0,
        "ttl_mean": 0.0,
        "ttl_std": 0.0,
        "src_port_entropy": 0.0,
        "flow_count": 0,
        "udp_ratio": 0.0,
        "pkt_rate_variation": 0.0,
    }
    
    if not pkt_list:
        return features
    
    # Working variables
    ttls = []
    src_ips = []
    src_ports = []
    arrival_times = []
    last_time = None
    frag_bytes = 0
    flow_map = {}
    udp_count = 0
    per_second = {}
    t0 = pkt_list[0].time
    
    for pkt in pkt_list:
        sec = int(pkt.time - t0)
        per_second[sec] = per_second.get(sec, 0) + 1
        
        if not pkt.haslayer(IP):
            continue
        
        ip = pkt[IP]
        ttls.append(ip.ttl)
        src_ips.append(ip.src)
        
        if ip.flags.MF or ip.frag > 0:
            features["fragment_count"] += 1
            frag_bytes += len(ip)
        
        if last_time is not None:
            dt = pkt.time - last_time
            if dt > 0:
                arrival_times.append(dt)
        last_time = pkt.time
        
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            src_ports.append(tcp.sport)
            fkey = (ip.src, ip.dst, tcp.sport, tcp.dport)
            flow_map[fkey] = flow_map.get(fkey, 0) + 1
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            udp_count += 1
            src_ports.append(udp.sport)
            fkey = (ip.src, ip.dst, udp.sport, udp.dport)
            flow_map[fkey] = flow_map.get(fkey, 0) + 1
    
    # Calculations
    if features["pkt_count"] > 0:
        features["fragment_ratio"] = features["fragment_count"] / features["pkt_count"]
        features["udp_ratio"] = udp_count / features["pkt_count"]
    
    if features["fragment_count"] > 0:
        features["avg_fragment_size"] = frag_bytes / features["fragment_count"]
    
    if ttls:
        mean = sum(ttls) / len(ttls)
        var = sum((t - mean) ** 2 for t in ttls) / len(ttls)
        features["ttl_mean"] = mean
        features["ttl_std"] = math.sqrt(var)
    
    if arrival_times:
        m = sum(arrival_times) / len(arrival_times)
        v = sum((x - m) ** 2 for x in arrival_times) / len(arrival_times)
        features["inter_arrival_mean"] = m
        features["inter_arrival_std"] = math.sqrt(v)
    
    features["src_port_entropy"] = calculate_entropy(src_ports)
    features["flow_count"] = len(flow_map)
    
    vals = list(per_second.values())
    if vals:
        m = sum(vals) / len(vals)
        v = sum((v - m) ** 2 for v in vals) / len(vals)
        features["pkt_rate_variation"] = math.sqrt(v)
    
    return features


# FEATURE EXTRACTOR 4: Reconnaissance (Model 6)
def extract_recon_features(pkt_list):
    feats = {
        "unique_dst_ports": 0, "unique_dst_ports_ratio": 0.0, "syn_ratio": 0.0, "syn_count": 0, "dst_ip_count": 0,
        "fin_count": 0, "rst_count": 0, "null_flag_count": 0, "xmas_flag_count": 0,
        "ttl_mean": 0.0, "ttl_std": 0.0, "inter_arrival_mean": 0.0, "inter_arrival_std": 0.0,
        "src_port_entropy": 0.0, "incomplete_handshake_ratio": 0.0, "pkt_rate_variation": 0.0,
        "flow_count": 0, "pkt_count": len(pkt_list), "byte_count": sum(len(p) for p in pkt_list),
    }

    if not pkt_list: return feats

    ttls, arrival_times, src_ports = [], [], []
    dst_ports, dst_ips = set(), set()
    tcp_flows, per_second = {}, {}
    last_ts = None
    start_ts = pkt_list[0].time

    for pkt in pkt_list:
        sec = int(pkt.time - start_ts)
        per_second[sec] = per_second.get(sec, 0) + 1

        if not pkt.haslayer(IP): continue
        ip = pkt[IP]
        ttls.append(ip.ttl)
        dst_ips.add(ip.dst)

        if last_ts is not None:
            dt = pkt.time - last_ts
            if dt > 0: arrival_times.append(dt)
        last_ts = pkt.time

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            src_ports.append(tcp.sport)
            dst_ports.add(tcp.dport)
            flags = tcp.flags
            if flags.S: feats["syn_count"] += 1
            if flags.F: feats["fin_count"] += 1
            if flags.R: feats["rst_count"] += 1
            if int(flags) == 0: feats["null_flag_count"] += 1
            if flags.F and flags.P and flags.U: feats["xmas_flag_count"] += 1
            fkey = (ip.src, ip.dst, tcp.sport, tcp.dport)
            if fkey not in tcp_flows: tcp_flows[fkey] = {"syn": False, "fin_rst": False}
            if flags.S and not flags.A: tcp_flows[fkey]["syn"] = True
            if flags.F or flags.R: tcp_flows[fkey]["fin_rst"] = True
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            src_ports.append(udp.sport)
            dst_ports.add(udp.dport)

    feats["unique_dst_ports"] = len(dst_ports)
    feats["dst_ip_count"] = len(dst_ips)
    if feats["pkt_count"] > 0:
        feats["unique_dst_ports_ratio"] = len(dst_ports) / feats["pkt_count"]
        feats["syn_ratio"] = feats["syn_count"] / feats["pkt_count"]

    if ttls:
        mean = sum(ttls)/len(ttls)
        var = sum((t - mean)**2 for t in ttls) / len(ttls)
        feats["ttl_mean"] = mean
        feats["ttl_std"] = math.sqrt(var)

    if arrival_times:
        mean = sum(arrival_times)/len(arrival_times)
        var = sum((x - mean)**2 for x in arrival_times) / len(arrival_times)
        feats["inter_arrival_mean"] = mean
        feats["inter_arrival_std"] = math.sqrt(var)

    feats["src_port_entropy"] = calculate_entropy(src_ports)
    if tcp_flows:
        incomplete = sum(1 for f in tcp_flows.values() if f["syn"] and not f["fin_rst"])
        feats["incomplete_handshake_ratio"] = incomplete / len(tcp_flows)
        feats["flow_count"] = len(tcp_flows)

    vals = list(per_second.values())
    if vals:
        mean = sum(vals)/len(vals)
        var = sum((v - mean)**2 for v in vals)/len(vals)
        feats["pkt_rate_variation"] = math.sqrt(var)

    return feats
# MODEL LOADERS & RUNNERS
def load_all_models():
    """Load all ML models with proper error handling"""
    print("** Loading models...")

    # Model 1 (Primary DDoS)
    try:
        m1 = joblib.load(MODEL1_PATH)
        e1 = joblib.load(MODEL1_ENCODER_PATH)
        f1 = joblib.load(MODEL1_FEATURES_PATH)
        print("+Model-1 (DDoS Primary) loaded")
    except Exception as e:
        print(f"**Failed to load Model-1: {e}")
        sys.exit(1)

    # Model 2 (DDoS Secondary)
    try:
        m2 = joblib.load(MODEL2_PATH)
        s2 = joblib.load(MODEL2_SCALER_PATH)
        e2 = joblib.load(MODEL2_ENCODER_PATH)
        if os.path.exists(M2_FEAT_PATH):
            try:
                f2 = joblib.load(M2_FEAT_PATH)
            except:
                with open(M2_FEAT_PATH, 'r') as f:
                    f2 = json.load(f)
        else:
            f2 = f1
        print("+Model-2 (DDoS Secondary) loaded")
    except Exception as e:
        print(f" **Failed to load Model-2: {e}")
        sys.exit(1)

    # Model 3 (Teardrop Verification)
    try:
        m3 = joblib.load(MODEL3_PATH)
        s3 = joblib.load(MODEL3_SCALER_PATH)
        e3 = joblib.load(MODEL3_ENCODER_PATH)
        if os.path.exists(MODEL3_FEATURE_PATH):
            with open(MODEL3_FEATURE_PATH, "r") as f:
                f3_order = json.load(f)
        else:
            f3_order = ["pkt_count", "byte_count", "fragment_count", "fragment_ratio", 
                       "avg_fragment_size", "inter_arrival_mean", "inter_arrival_std",
                       "ttl_mean", "ttl_std", "src_port_entropy", "flow_count", 
                       "udp_ratio", "pkt_rate_variation"]
        print("+Model-3 (Teardrop Verification) loaded")
    except Exception as e:
        print(f"Model-3 not available: {e}")
        m3 = None
        s3 = None
        e3 = None
        f3_order = None

    # Model 4 (Mixed Attack Verification)
    try:
        m4_model = joblib.load(MODEL4_PATH)
        m4_scaler = joblib.load(MODEL4_SCALER_PATH)
        m4_encoder = joblib.load(MODEL4_ENCODER_PATH)
        with open(MODEL4_FEATURE_PATH, "r") as f:
            m4_order = json.load(f)
        print("+Model-4 (Mixed Attack Verification) loaded")
    except Exception as e:
        print(f"Model-4 not available: {e}")
        m4_model = None
        m4_scaler = None
        m4_encoder = None
        m4_order = None

    # Model 6 (Reconnaissance)
    try:
        m6 = joblib.load(M6_PATH)
        s6 = joblib.load(M6_SCALER_PATH)
        e6 = joblib.load(M6_ENCODER_PATH)
        with open(M6_FEAT_PATH, "r") as f:
            f6_order = json.load(f)
        print("+Model-6 (Reconnaissance) loaded")
    except Exception as e:
        print(f"**Failed to load Model-6: {e}")
        sys.exit(1)

    return (m1, e1, f1), (m2, s2, e2, f2), (m3, s3, e3, f3_order), (m4_model, m4_scaler, m4_encoder, m4_order), (m6, s6, e6, f6_order)


def run_model1(m1, packets):
    """Run Model 1 (Primary DDoS Detection)"""
    model, enc, order = m1
    feats = extract_model1_features(packets)
    df = pd.DataFrame([feats], columns=order)
    pred = model.predict(df)
    return enc.inverse_transform(pred)[0], feats


def run_model2(m2, packets):
    """Run Model 2 (Secondary DDoS Detection)"""
    model, scaler, enc, order = m2
    feats = extract_model2_features(packets)
    df = pd.DataFrame([feats])
    X = scaler.transform(df.values)
    pred = model.predict(X)
    return enc.inverse_transform(pred)[0], feats


def run_model3(m3, packets):
    """Run Model 3 (Teardrop Verification)"""
    model, scaler, enc, order = m3

    if model is None:
        feats = extract_model3_features(packets)
        if feats['fragment_ratio'] > TEARDROP_MIN_FRAGMENT_RATIO and feats['udp_ratio'] > 0.5:
            return "Teardrop", feats
        return "Normal", feats

    feats = extract_model3_features(packets)
    df = pd.DataFrame([feats], columns=order)

    try:
        X = scaler.transform(df.values)
        pred = model.predict(X)
        return enc.inverse_transform(pred)[0], feats
    except Exception as e:
        print(f"M3 prediction error: {e}, using heuristic")
        if feats['fragment_ratio'] > TEARDROP_MIN_FRAGMENT_RATIO and feats['udp_ratio'] > 0.5:
            return "Teardrop", feats
        return "Normal", feats


def run_model4(m4, model2_features):
    """Run Model 4 (Mixed Attack Verification)"""
    if not m4[0]:
        return None

    model, scaler, enc, order = m4
    ordered = {key: model2_features.get(key,0) for key in order}
    df = pd.DataFrame([ordered])
    X = scaler.transform(df.values)
    pred = model.predict(X)
    return enc.inverse_transform(pred)[0]


# ALERTING HELPER
def send_alert(label, features, type_desc="DDoS"):
    """Send alert through alerter system"""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{type_desc.upper()} ALERT: {label} at {ts}")
    details = {k: features.get(k, 0) for k in ["pps", "udp_ratio", "src_ip_entropy", "unique_dst_ports"]}
    alerter.trigger_alert(label, ts, f"{type_desc} Detection", details)
# GLOBAL MODEL INITIALIZATION
try:
    m1_g, m2_g, m3_g, m4_g, m6_g = load_all_models()
    print("\nAll models loaded successfully!\n")
except Exception as e:
    print(f"\nCritical Error: Failed to load models: {e}")
    sys.exit(1)
# MAIN PIPELINE FUNCTION
def process_ddos_packets(packets, rolling_pps_state):
    if not packets:
        return "NoTraffic", rolling_pps_state

    # STAGE 1: PRIMARY DDoS DETECTION (MODEL 1)
    label1, f1 = run_model1(m1_g, packets)

    # CRITICAL: Ignore Slowloris completely
    if label1 == "Slowloris":
        print("Normal")
        return "Normal", rolling_pps_state

    # Extract key metrics
    pps = f1.get("pps", 0)

    # Update rolling PPS average
    r_pps = rolling_pps_state["pps"]
    if r_pps is None:
        r_pps = pps
    else:
        r_pps = 0.8 * r_pps + 0.2 * pps
    rolling_pps_state["pps"] = r_pps
    # DDoS ATTACK DETECTED BY MODEL 1
    if label1 != "Normal":
        # Special handling for Teardrop - needs verification
        if label1 in ("Teardrop_Attack", "Teardrop"):
            print("⚠️Teardrop suspected by M1, verifying with M3...")
            label3, f3 = run_model3(m3_g, packets)  

            if label3 != "Normal":
                send_alert("Teardrop_Verified", f1)
                return "Teardrop_Verified", rolling_pps_state
            else:
                print("✓ M3 rejected Teardrop - likely false positive")
                return "Teardrop_Rejected", rolling_pps_state

        # All other DDoS attacks from Model-1
        send_alert(f"Model1_{label1}", f1, type_desc="DDoS")
        return label1, rolling_pps_state

    # STAGE 2: MODEL-1 IS NORMAL → ALWAYS RUN MODEL-2
    print("+Model-1 reports Normal → Running Model-2 for secondary analysis...")

    label2, f2 = run_model2(m2_g, packets)

    # Ignore Slowloris from Model-2
    if label2 == "Slowloris":
        print("Normal")
        return "Normal", rolling_pps_state

    # Mixed attack handling
    if label2 == "Mixed_Attack":
        if m4_g[0] is not None:
            print("ixed Attack suspected by M2 → verifying with Model-4...")
            verdict4 = run_model4(m4_g, f2)

            if verdict4 == "Mixed_Attack":
                send_alert("Mixed_Attack_Verified", f2, type_desc="DDoS")
                return "Mixed_Attack", rolling_pps_state
            else:
                print(f"+M4 rejected Mixed Attack ({verdict4}) → Proceeding to Recon...")
        else:
            print("odel-4 unavailable → Mixed Attack Unverified")
            send_alert("Mixed_Attack_Unverified", f2, type_desc="DDoS")
            return "Mixed_Attack_Unverified", rolling_pps_state

    # Any other DDoS label from Model-2
    if label2 != "Normal":
        send_alert(f"Model2_{label2}", f2, type_desc="DDoS")
        return label2, rolling_pps_state

    # STAGE 3: MODEL-1 NORMAL + MODEL-2 NORMAL → RUN RECON (MODEL-6)
    print(" No DDoS detected → Running Reconnaissance Model (Model-6)...")

    try:
        f6 = extract_recon_features(packets)
        df6 = pd.DataFrame([f6], columns=m6_g[3])
        X6 = m6_g[1].transform(df6.values)
        pred6 = m6_g[0].predict(X6)
        label6 = m6_g[2].inverse_transform(pred6)[0]

        if label6 != "Normal":
            print(f"Reconnaissance Detected: {label6}")
            send_alert(label6, f6, type_desc="Reconnaissance")
            return label6, rolling_pps_state
        else:
            print("Traffic is Normal")

    except Exception as e:
        print(f"Recon model error: {e}")

    return "Normal", rolling_pps_state
