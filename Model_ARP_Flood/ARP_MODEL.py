#!/usr/bin/env python3
import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

# ============================================================
# PATH SETUP
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join("Model_ARP_Flood.json")

MODEL_PATH = os.path.join(BASE_DIR, "model_arp.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "scaler_arp.pkl")
ENCODER_PATH = os.path.join(BASE_DIR, "encoder_arp.pkl")
FEATURE_ORDER_PATH = os.path.join(BASE_DIR, "feature_order_arp.json")

# ============================================================
# LOAD DATA
# ============================================================
print("====================================================")
print("          ARP Flood Detection Trainer")
print("====================================================")

if not os.path.exists(DATA_FILE):
    print(f"ERROR: Dataset not found: {DATA_FILE}")
    exit(1)

with open(DATA_FILE, "r") as f:
    data = json.load(f)

print(f"[+] Loaded dataset with {len(data)} blocks")

# ============================================================
# EXTRACT FEATURES
# ============================================================
X = []
y = []

for entry in data:
    feat = entry["features"]

    X.append([
        feat["arp_count"],
        feat["unique_senders"],
        feat["unique_targets"],
        feat["broadcast_count"],
        feat["broadcast_ratio"],
        feat["mac_conflict_count"],
        feat["mac_conflict_ratio"],
        feat["mean_interval"],
        feat["variance_interval"],
        feat["interval_count"]
    ])

    y.append(feat["label"])   # Normal or ARP_Flood

# Feature names (order is important)
feature_names = [
    "arp_count",
    "unique_senders",
    "unique_targets",
    "broadcast_count",
    "broadcast_ratio",
    "mac_conflict_count",
    "mac_conflict_ratio",
    "mean_interval",
    "variance_interval",
    "interval_count"
]

X = np.array(X)

# ============================================================
# LABEL ENCODING
# ============================================================
encoder = LabelEncoder()
y_encoded = encoder.fit_transform(y)

print("\n[+] Label mappings:")
for i, label in enumerate(encoder.classes_):
    print(f"  {label} -> {i}")

# ============================================================
# SCALING
# ============================================================
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# ============================================================
# TRAIN-TEST SPLIT
# ============================================================
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y_encoded, test_size=0.2, random_state=42, shuffle=True
)

# ============================================================
# TRAIN MODEL
# ============================================================
print("\n[+] Training RandomForest model...")

model = RandomForestClassifier(
    n_estimators=200,
    max_depth=12,
    min_samples_split=3,
    bootstrap=True,
    random_state=42
)

model.fit(X_train, y_train)

print("[+] Training complete!")

# ============================================================
# EVALUATE
# ============================================================
y_pred = model.predict(X_test)

acc = accuracy_score(y_test, y_pred)
print(f"\n[✓] Accuracy: {acc * 100:.2f}%")

print("\n[✓] Classification Report:")
print(classification_report(y_test, y_pred, target_names=encoder.classes_))

print("\n[✓] Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# ============================================================
# SAVE ARTIFACTS
# ============================================================
joblib.dump(model, MODEL_PATH)
joblib.dump(scaler, SCALER_PATH)
joblib.dump(encoder, ENCODER_PATH)

with open(FEATURE_ORDER_PATH, "w") as f:
    json.dump(feature_names, f, indent=2)

print("\n====================================================")
print("[+] Model saved as:", MODEL_PATH)
print("[+] Scaler saved as:", SCALER_PATH)
print("[+] Encoder saved as:", ENCODER_PATH)
print("[+] Feature order saved as:", FEATURE_ORDER_PATH)
print("====================================================")
print("Training complete. You can now integrate Model_ARP_Flood!")
