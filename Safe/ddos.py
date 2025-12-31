#!/usr/bin/env python3
import os
import sys
import time
import math
import json
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP
import pandas as pd
import joblib

# ============================================================
# PATH SETUP
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)

# Model-1 paths
MODEL1_DIR = os.path.join(PROJECT_ROOT, "Model1_ddos")
MODEL1_PATH = os.path.join(MODEL1_DIR, "ddos_detection_model.pkl")
MODEL1_ENCODER_PATH = os.path.join(MODEL1_DIR, "label_encoder.pkl")
MODEL1_FEATURES_PATH = os.path.join(MODEL1_DIR, "feature_order.pkl")

# Model-2 paths
MODEL2_DIR = os.path.join(PROJECT_ROOT, "Model2_ddos")
MODEL2_PATH = os.path.join(MODEL2_DIR, "model2_model.pkl")
MODEL2_SCALER_PATH = os.path.join(MODEL2_DIR, "model2_scaler.pkl")
MODEL2_ENCODER_PATH = os.path.join(MODEL2_DIR, "model2_label_encoder.pkl")

# Model-3 paths
MODEL3_DIR = os.path.join(PROJECT_ROOT, "Model3_ddos")
MODEL3_PATH = os.path.join(MODEL3_DIR, "model3_model.pkl")
MODEL3_SCALER_PATH = os.path.join(MODEL3_DIR, "model3_scaler.pkl")
MODEL3_ENCODER_PATH = os.path.join(MODEL3_DIR, "model3_label_encoder.pkl")

# Model-4 paths (Mixed Attack Verification)
MODEL4_DIR = os.path.join(PROJECT_ROOT, "Model4_ddos")
MODEL4_PATH = os.path.join(MODEL4_DIR, "model4_model.pkl")
MODEL4_SCALER_PATH = os.path.join(MODEL4_DIR, "model4_scaler.pkl")
MODEL4_ENCODER_PATH = os.path.join(MODEL4_DIR, "model4_label_encoder.pkl")
MODEL4_FEATURE_PATH = os.path.join(MODEL4_DIR, "feature_order_model4.json")

# Import alerter from Basic_Functions
sys.path.insert(0, os.path.join(PROJECT_ROOT, "Basic_Functions"))
import alerter  # noqa: E402

# Import Recon model (from Main_Functions)
sys.path.insert(0, BASE_DIR)
import Recon  # noqa: E402

# ============================================================
# CONFIG
# ============================================================
WINDOW = 10
IFACE = "eth0"
SPOOFED_IP_ENTROPY_THRESHOLD = 7.0

UDP_RATIO_THRESHOLD = 0.7
ENTROPY_THRESHOLD = 4.0
MIN_FRAGMENT_RATIO_SUSPICIOUS = 0.01

TEARDROP_MIN_FRAGMENT_RATIO = 0.3


# ============================================================
# UTILS
# ============================================================
def calculate_entropy(values):
    if not values:
        return 0.0
    freq = {v: values.count(v) for v in set(values)}
    total = len(values)
    return -sum((c / total) * math.log2(c / total) for c in freq.values() if c > 0)


# ============================================================
# MODEL-1 FEATURE EXTRACTION
# (UNCHANGED - DO NOT MODIFY)
# ============================================================
def extract_model1_features(pkt_list):
    features = {
        "pkt_count": len(pkt_list),
        "byte_count": sum(len(pkt) for pkt in pkt_list),
        "unique_src_ips": 0,
        "unique_dst_ports": 0,
        "syn_count": 0,
        "syn_ack_count": 0,
        "udp_count": 0,
        "icmp_count": 0,
        "avg_pkt_size": 0.0,
        "pps": 0.0,
        "bps": 0.0,
        "syn_ratio": 0.0,
        "udp_ratio": 0.0,
        "src_ip_entropy": 0.0,
        "icmp_ratio": 0.0,
        "avg_flow_duration": 0.0,
        "unique_dst_ports_ratio": 0.0,
        "fragment_count": 0,
        "fragment_ratio": 0.0,
        "avg_fragment_size": 0.0,
        "connection_count": 0,
        "request_rate": 0.0,
        "avg_pkts_per_flow": 0.0,
        "psh_ack_ratio": 0.0,
    }

    src_ips = []
    dst_ports = set()
    flows = {}
    fragment_byte_count = 0
    http_request_count = 0
    psh_ack_count = 0

    for pkt in pkt_list:
        if not pkt.haslayer(IP):
            continue

        ip = pkt[IP]
        src_ips.append(ip.src)

        if ip.flags.MF or ip.frag > 0:
            features["fragment_count"] += 1
            fragment_byte_count += len(ip)

        flow_key = None
        if pkt.haslayer(TCP) or pkt.haslayer(UDP):
            protocol = "TCP" if pkt.haslayer(TCP) else "UDP"
            flow_key = (
                tuple(sorted(((ip.src, pkt.sport), (ip.dst, pkt.dport))))
                + (protocol,)
            )

            if flow_key not in flows:
                flows[flow_key] = {
                    "pkt_count": 0,
                    "start_time": pkt.time,
                    "last_time": pkt.time,
                    "has_fin_rst": False,
                }

            flows[flow_key]["pkt_count"] += 1
            flows[flow_key]["last_time"] = pkt.time

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            dst_ports.add(tcp.dport)

            if tcp.flags.S and not tcp.flags.A:
                features["syn_count"] += 1
            if tcp.flags.S and tcp.flags.A:
                features["syn_ack_count"] += 1
            if tcp.flags.P and tcp.flags.A:
                psh_ack_count += 1

            if tcp.dport == 80 and pkt.haslayer("Raw"):
                payload = pkt["Raw"].load.decode(errors="ignore").upper()
                if payload.startswith("GET") or payload.startswith("POST"):
                    http_request_count += 1

            if tcp.flags.F or tcp.flags.R:
                if flow_key:
                    flows[flow_key]["has_fin_rst"] = True

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
            features["avg_fragment_size"] = (
                fragment_byte_count / features["fragment_count"]
            )

    return features


# ============================================================
# MODEL-2 + MODEL-3 EXTRACTION
# (UNCHANGED)
# ============================================================
def extract_model2_features(pkt_list):
    extra = {
        "fin_count": 0,
        "rst_count": 0,
        "null_flag_count": 0,
        "xmas_flag_count": 0,
        "ttl_mean": 0.0,
        "ttl_std": 0.0,
        "inter_arrival_mean": 0.0,
        "inter_arrival_std": 0.0,
        "src_port_entropy": 0.0,
        "incomplete_handshake_ratio": 0.0,
        "pkt_rate_variation": 0.0,
        "flow_count": 0,
        "pkt_count": len(pkt_list),
        "byte_count": sum(len(pkt) for pkt in pkt_list),
    }

    if not pkt_list:
        return extra

    ttls = []
    arrival_times = []
    last_time = None
    src_ports = []
    tcp_flows = {}
    per_second = {}
    start_ts = pkt_list[0].time

    for pkt in pkt_list:
        sec = int(pkt.time - start_ts)
        per_second[sec] = per_second.get(sec, 0) + 1

        if not pkt.haslayer(IP):
            continue

        ip = pkt[IP]
        ttls.append(ip.ttl)

        if last_time is not None:
            dt = pkt.time - last_time
            if dt > 0:
                arrival_times.append(dt)
        last_time = pkt.time

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            src_ports.append(tcp.sport)

            flags = tcp.flags
            if flags.F:
                extra["fin_count"] += 1
            if flags.R:
                extra["rst_count"] += 1
            if int(flags) == 0:
                extra["null_flag_count"] += 1
            if flags.F and flags.P and flags.U:
                extra["xmas_flag_count"] += 1

            fkey = (ip.src, ip.dst, tcp.sport, tcp.dport)
            if fkey not in tcp_flows:
                tcp_flows[fkey] = {"syn": False, "fin_rst": False}
            if flags.S and not flags.A:
                tcp_flows[fkey]["syn"] = True
            if flags.F or flags.R:
                tcp_flows[fkey]["fin_rst"] = True

    if ttls:
        mean = sum(ttls) / len(ttls)
        var = sum((t - mean) ** 2 for t in ttls) / len(ttls)
        extra["ttl_mean"] = mean
        extra["ttl_std"] = math.sqrt(var)

    if arrival_times:
        mean = sum(arrival_times) / len(arrival_times)
        var = sum((x - mean) ** 2 for x in arrival_times) / len(arrival_times)
        extra["inter_arrival_mean"] = mean
        extra["inter_arrival_std"] = math.sqrt(var)

    extra["src_port_entropy"] = calculate_entropy(src_ports)

    if tcp_flows:
        incomplete = sum(
            1 for f in tcp_flows.values() if f["syn"] and not f["fin_rst"]
        )
        extra["incomplete_handshake_ratio"] = incomplete / len(tcp_flows)
        extra["flow_count"] = len(tcp_flows)

    vals = list(per_second.values())
    if vals:
        mean = sum(vals) / len(vals)
        var = sum((v - mean) ** 2 for v in vals) / len(vals)
        extra["pkt_rate_variation"] = math.sqrt(var)

    return extra


def extract_model3_features(pkt_list):
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

    ttls = []
    arrival_times = []
    last_ts = None
    src_ports = []
    flows = {}
    fragment_bytes = 0
    per_second = {}
    start_ts = pkt_list[0].time

    for pkt in pkt_list:
        sec = int(pkt.time - start_ts)
        per_second[sec] = per_second.get(sec, 0) + 1

        if not pkt.haslayer(IP):
            continue

        ip = pkt[IP]
        ttls.append(ip.ttl)

        if last_ts is not None:
            dt = pkt.time - last_ts
            if dt > 0:
                arrival_times.append(dt)
        last_ts = pkt.time

        if ip.flags.MF or ip.frag > 0:
            features["fragment_count"] += 1
            fragment_bytes += len(ip)

        if pkt.haslayer(TCP):
            t = pkt[TCP]
            src_ports.append(t.sport)
            flows[(ip.src, ip.dst, t.sport, t.dport)] = True

        if pkt.haslayer(UDP):
            u = pkt[UDP]
            src_ports.append(u.sport)
            flows[(ip.src, ip.dst, u.sport, u.dport)] = True

    if ttls:
        mean = sum(ttls) / len(ttls)
        var = sum((t - mean) ** 2 for t in ttls) / len(ttls)
        features["ttl_mean"] = mean
        features["ttl_std"] = math.sqrt(var)

    if arrival_times:
        mean = sum(arrival_times) / len(arrival_times)
        var = sum((x - mean) ** 2 for x in arrival_times) / len(arrival_times)
        features["inter_arrival_mean"] = mean
        features["inter_arrival_std"] = math.sqrt(var)

    total = len(pkt_list)
    if total > 0:
        features["fragment_ratio"] = features["fragment_count"] / total
        udp_count = sum(1 for pkt in pkt_list if pkt.haslayer(UDP))
        features["udp_ratio"] = udp_count / total

    if features["fragment_count"] > 0:
        features["avg_fragment_size"] = (
            fragment_bytes / features["fragment_count"]
        )

    features["src_port_entropy"] = calculate_entropy(src_ports)
    features["flow_count"] = len(flows)

    vals = list(per_second.values())
    if vals:
        mean = sum(vals) / len(vals)
        var = sum((v - mean) ** 2 for v in vals) / len(vals)
        features["pkt_rate_variation"] = math.sqrt(var)

    return features


# ============================================================
# MODEL PREDICT HELPERS
# ============================================================
def load_all_models():
    print("** Loading models...")

    # Model 1
    m1 = joblib.load(MODEL1_PATH)
    e1 = joblib.load(MODEL1_ENCODER_PATH)
    f1 = joblib.load(MODEL1_FEATURES_PATH)

    # Model 2
    m2 = joblib.load(MODEL2_PATH)
    s2 = joblib.load(MODEL2_SCALER_PATH)
    e2 = joblib.load(MODEL2_ENCODER_PATH)

    # Model 3
    m3 = joblib.load(MODEL3_PATH)
    s3 = joblib.load(MODEL3_SCALER_PATH)
    e3 = joblib.load(MODEL3_ENCODER_PATH)

    # Model 4 (NEW)
    try:
        m4_model = joblib.load(MODEL4_PATH)
        m4_scaler = joblib.load(MODEL4_SCALER_PATH)
        m4_encoder = joblib.load(MODEL4_ENCODER_PATH)
        with open(MODEL4_FEATURE_PATH, "r") as f:
            m4_order = json.load(f)
    except Exception as e:
        print(f"++ Failed to load Model-4: {e} ++")
        sys.exit(1)

    print("All models loaded.\n")
    return (m1, e1, f1), (m2, s2, e2), (m3, s3, e3), (m4_model, m4_scaler, m4_encoder, m4_order)


def run_model1(m1, packets):
    model, enc, order = m1
    feats = extract_model1_features(packets)
    df = pd.DataFrame([feats], columns=order)
    pred = model.predict(df)
    return enc.inverse_transform(pred)[0], feats


def run_model2(m2, packets):
    model, scaler, enc = m2
    feats = extract_model2_features(packets)
    df = pd.DataFrame([feats])
    X = scaler.transform(df)
    pred = model.predict(X)
    return enc.inverse_transform(pred)[0], feats


def run_model3(m3, packets):
    model, scaler, enc = m3
    feats = extract_model3_features(packets)
    df = pd.DataFrame([feats])
    X = scaler.transform(df)
    pred = model.predict(X)
    return enc.inverse_transform(pred)[0], feats


# NEW MODEL-4 HELPER
def run_model4(m4, model2_features):
    model, scaler, enc, order = m4

    ordered = {key: model2_features[key] for key in order}

    df = pd.DataFrame([ordered])
    X = scaler.transform(df)

    pred = model.predict(X)
    return enc.inverse_transform(pred)[0]


def build_source_info(pkts, ent):
    if ent > SPOOFED_IP_ENTROPY_THRESHOLD:
        return "Spoofed IPs (Distributed Attack)"
    ips = [p[IP].src for p in pkts if p.haslayer(IP)]
    if not ips:
        return "Source unknown"
    most = max(set(ips), key=ips.count)
    return f"{most} (Low Entropy Source)"


# ============================================================
# MASTER LOOP
# ============================================================
if __name__ == "__main__":
    try:
        m1, m2, m3, m4 = load_all_models()
    except Exception as e:
        print(f"Failed to load models: {e}")
        sys.exit(1)

    rolling_pps = None
    print(f"MASTER DETECTOR STARTED on {IFACE} (window={WINDOW}s)\n")

    while True:
        try:
            packets = sniff(iface=IFACE, timeout=WINDOW, store=True)
            if not packets:
                print(f"[{datetime.now()}] No traffic.")
                continue

            label1, f1 = run_model1(m1, packets)
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            pps = f1["pps"]
            udp = f1["udp_ratio"]
            frag = f1["fragment_ratio"]
            ent = f1["src_ip_entropy"]

            if rolling_pps is None:
                rolling_pps = pps
            else:
                rolling_pps = 0.8 * rolling_pps + 0.2 * pps

            # ----------------------------------------------------
            # MODEL 1: NORMAL CASE
            # ----------------------------------------------------
            if label1 == "Normal":
                print(f"[{ts}] M1: Normal | PPS={pps:.2f} UDP={udp:.2f} Frag={frag:.3f}")

                abnormal = (
                    pps > max(150, 2 * rolling_pps)
                    or udp > UDP_RATIO_THRESHOLD
                    or ent > ENTROPY_THRESHOLD
                    or frag > MIN_FRAGMENT_RATIO_SUSPICIOUS
                )

                if abnormal:
                    print("   -->Abnormal traffic — activating Model-2")
                    label2, f2 = run_model2(m2, packets)

                    if label2 == "Slowloris":
                        print("   -->Model-2 predicted Slowloris — ignoring.")
                        continue

                    # ===============================
                    # NEW LOGIC: MODEL-4 VERIFICATION
                    # ===============================
                    if label2 == "Mixed_Attack":
                        print("   -->Model-2 detected Mixed_Attack — verifying with Model-4...")

                        verdict4 = run_model4(m4, f2)
                        print(f"   -->Model-4 verdict: {verdict4}")

                        if verdict4 != "Mixed_Attack":
                            print("   -->Model-4 rejected — FALSE Mixed attack removed.")
                            continue
                        else:
                            print("   -->Model-4 confirmed TRUE Mixed Attack.")

                    # ===============================
                    # (END OF NEW LOGIC)
                    # ===============================

                    if label2 != "Normal":
                        src = build_source_info(packets, ent)
                        details = {
                            "pps": pps,
                            "src_ip_entropy": ent,
                            "udp_ratio": udp,
                            "fragment_ratio": frag,
                        }

                        print("=" * 60)
                        print(f"ALERT (Model-2): {label2}")
                        print(f"   Time: {ts}")
                        print("=" * 60)

                        alerter.trigger_alert(
                            attack_type=f"Model2_{label2}",
                            timestamp=ts,
                            source_info=src,
                            details_dict=details,
                        )
                        # Attack confirmed by DDoS pipeline, skip recon
                        continue
                    else:
                        print(" -->Model-2 also sees Normal.")

                # If we reach here:
                # - Model-1 is Normal
                # - Either traffic was not abnormal OR Model-2 also said Normal
                # => Now run Recon model on same packet window
                try:
                    print("   -->Running Recon Model...")
                    recon_label = Recon.check_recon(packets)
                    # Recon.check_recon already prints & alerts; here we just log
                    print(f"   -->Recon verdict: {recon_label}")
                except Exception as e:
                    print(f"   -->Recon Model Error: {e}")

                continue

            # ----------------------------------------------------
            # TEARDROP LOGIC (UNCHANGED)
            # ----------------------------------------------------
            if label1 == "Teardrop_Attack":
                print(f"[{ts}] M1: Teardrop | PPS={pps:.2f} Frag={frag:.3f}")

                if frag < TEARDROP_MIN_FRAGMENT_RATIO:
                    print("   -->Frag too low — ignoring.")
                    continue

                label3, f3 = run_model3(m3, packets)
                print(f"   -->Model-3 verdict: {label3}")

                if label3 != "Teardrop":
                    print("   -->Model-3 rejects — false positive removed.")
                    continue

                src = build_source_info(packets, ent)
                details = {
                    "pps": pps,
                    "src_ip_entropy": ent,
                    "udp_ratio": udp,
                    "fragment_ratio": frag,
                }

                print("=" * 60)
                print("ALERT (Teardrop verified)")
                print(f"   Time: {ts}")
                print("=" * 60)

                alerter.trigger_alert(
                    attack_type="Teardrop_Attack_Verified",
                    timestamp=ts,
                    source_info=src,
                    details_dict=details,
                )
                continue

            # ----------------------------------------------------
            # MODEL-1 OTHER ATTACKS (UNCHANGED)
            # ----------------------------------------------------
            src = build_source_info(packets, ent)
            details = {
                "pps": pps,
                "src_ip_entropy": ent,
                "udp_ratio": udp,
                "fragment_ratio": frag,
            }

            print("=" * 60)
            print(f"ALERT (Model-1): {label1}")
            print(f"   Time: {ts}")
            print("=" * 60)

            alerter.trigger_alert(
                attack_type=f"Model1_{label1}",
                timestamp=ts,
                source_info=src,
                details_dict=details,
            )

        except KeyboardInterrupt:
            print("\nStopped.")
            sys.exit(0)

        except Exception as e:
            print(f"Error: {e}")
            time.sleep(3)
