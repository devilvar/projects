#!/usr/bin/env python3
import os
import sys
import json
import math
import joblib
import pandas as pd
from datetime import datetime
from scapy.all import IP, TCP, UDP

# ---------------------- PATH SETUP --------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)

MODEL_DIR = os.path.join(PROJECT_ROOT, "Model_Recon")
MODEL_PATH   = os.path.join(MODEL_DIR, "model6_recon.pkl")
SCALER_PATH  = os.path.join(MODEL_DIR, "scaler6_recon.pkl")
ENCODER_PATH = os.path.join(MODEL_DIR, "encoder6_recon.pkl")
ORDER_PATH   = os.path.join(MODEL_DIR, "feature_order6_recon.json")

# Import alerter
sys.path.insert(0, os.path.join(PROJECT_ROOT, "Basic_Functions"))
import alerter


# ---------------------- UTILS -------------------------------
def entropy(values):
    if not values:
        return 0.0
    freq = {v: values.count(v) for v in set(values)}
    total = len(values)
    return -sum((c/total)*math.log2(c/total) for c in freq.values())


# ---------------------- FEATURE EXTRACTION -------------------
def extract_recon_features(pkt_list):
    feats = {
        "unique_dst_ports": 0,
        "unique_dst_ports_ratio": 0.0,
        "syn_ratio": 0.0,
        "syn_count": 0,
        "dst_ip_count": 0,
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
        "byte_count": sum(len(p) for p in pkt_list)
    }

    if not pkt_list:
        return feats

    ttls = []
    arrivals = []
    last = None
    src_ports = []
    dst_ports = set()
    dst_ips = set()
    flows = {}
    per_sec = {}

    t0 = pkt_list[0].time

    for p in pkt_list:
        sec = int(p.time - t0)
        per_sec[sec] = per_sec.get(sec, 0) + 1

        if not p.haslayer(IP):
            continue

        ip = p[IP]
        ttls.append(ip.ttl)
        dst_ips.add(ip.dst)

        if last:
            dt = p.time - last
            if dt > 0:
                arrivals.append(dt)
        last = p.time

        # TCP
        if p.haslayer(TCP):
            tcp = p[TCP]
            dst_ports.add(tcp.dport)
            src_ports.append(tcp.sport)

            f = (ip.src, ip.dst, tcp.sport, tcp.dport)
            if f not in flows:
                flows[f] = {"syn": False, "fin_rst": False}

            flags = tcp.flags
            if flags.S:
                feats["syn_count"] += 1
                flows[f]["syn"] = True
            if flags.F:
                feats["fin_count"] += 1
                flows[f]["fin_rst"] = True
            if flags.R:
                feats["rst_count"] += 1

            if int(flags) == 0:
                feats["null_flag_count"] += 1
            if flags.F and flags.P and flags.U:
                feats["xmas_flag_count"] += 1

        # UDP
        elif p.haslayer(UDP):
            udp = p[UDP]
            dst_ports.add(udp.dport)
            src_ports.append(udp.sport)

    # Calculations
    feats["unique_dst_ports"] = len(dst_ports)
    feats["dst_ip_count"] = len(dst_ips)

    if feats["pkt_count"] > 0:
        feats["unique_dst_ports_ratio"] = len(dst_ports) / feats["pkt_count"]
        feats["syn_ratio"] = feats["syn_count"] / feats["pkt_count"]

    if ttls:
        mean = sum(ttls)/len(ttls)
        var = sum((t - mean)**2 for t in ttls)/len(ttls)
        feats["ttl_mean"] = mean
        feats["ttl_std"] = math.sqrt(var)

    if arrivals:
        m = sum(arrivals)/len(arrivals)
        v = sum((x-m)**2 for x in arrivals)/len(arrivals)
        feats["inter_arrival_mean"] = m
        feats["inter_arrival_std"] = math.sqrt(v)

    feats["src_port_entropy"] = entropy(src_ports)

    if flows:
        incomplete = sum(1 for f in flows.values() if f["syn"] and not f["fin_rst"])
        feats["incomplete_handshake_ratio"] = incomplete / len(flows)
        feats["flow_count"] = len(flows)

    vals = list(per_sec.values())
    if vals:
        m = sum(vals)/len(vals)
        v = sum((x-m)**2 for x in vals)/len(vals)
        feats["pkt_rate_variation"] = math.sqrt(v)

    return feats


# ---------------------- LOAD MODEL --------------------------
model  = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)
enc    = joblib.load(ENCODER_PATH)
with open(ORDER_PATH, "r") as f:
    order = json.load(f)


# ---------------------- MAIN API ----------------------------
def check_recon(packets):

    feats = extract_recon_features(packets)

    df = pd.DataFrame([[feats[k] for k in order]], columns=order)
    X = scaler.transform(df)

    pred = model.predict(X)[0]
    label = enc.inverse_transform([pred])[0]

    if label != "Normal":
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print("------------------------------------------------------")
        print(f"RECON DETECTED: {label}")
        print(f"Time: {ts}")
        print("------------------------------------------------------")

        alerter.trigger_alert(
            attack_type=f"Recon_{label}",
            timestamp=ts,
            source_info="Recon-Model",
            details_dict={"attack": label}
        )

    else:
        print("Recon Model: Normal")

    return label
