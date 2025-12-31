#!/usr/bin/env python3
import json
import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib

# ----------------------------------------------------
# PATHS
# ----------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(BASE_DIR, "model3_data.json")

MODEL_OUT = os.path.join(BASE_DIR, "model3_model.pkl")
SCALER_OUT = os.path.join(BASE_DIR, "model3_scaler.pkl")
ENCODER_OUT = os.path.join(BASE_DIR, "model3_label_encoder.pkl")

# ----------------------------------------------------
# LOAD DATA
# ----------------------------------------------------
print("📥 Loading dataset:", DATA_FILE)

try:
    with open(DATA_FILE, "r") as f:
        data = json.load(f)
except Exception as e:
    print("❌ ERROR reading dataset:", e)
    exit(1)

df = pd.DataFrame(data)
print(f"✔ Loaded {len(df)} samples.\n")

# Must contain labels
if "label" not in df.columns:
    print("❌ ERROR: 'label' column missing. Run labeling tool first.")
    exit(1)

# Drop rows with missing values
df = df.dropna()

y = df["label"]
X = df.drop(columns=["label"])

print("Feature count:", len(X.columns))
print("Labels:", y.unique(), "\n")

# ----------------------------------------------------
# ENCODE LABELS
# ----------------------------------------------------
encoder = LabelEncoder()
y_encoded = encoder.fit_transform(y)

# ----------------------------------------------------
# SCALE FEATURES
# ----------------------------------------------------
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# ----------------------------------------------------
# TRAIN-TEST SPLIT
# ----------------------------------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)

print("Training samples:", len(X_train))
print("Testing samples:", len(X_test), "\n")

# ----------------------------------------------------
# TRAIN MODEL
# ----------------------------------------------------
print("🧠 Training Model-3 (Teardrop Verifier)...\n")

model = RandomForestClassifier(
    n_estimators=300,
    max_depth=20,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

# ----------------------------------------------------
# EVALUATE
# ----------------------------------------------------
y_pred = model.predict(X_test)

acc = accuracy_score(y_test, y_pred)
print("✔ Accuracy:", acc)
print("\n📊 Classification Report:\n")
print(classification_report(y_test, y_pred, target_names=encoder.classes_))

# ----------------------------------------------------
# SAVE ARTIFACTS
# ----------------------------------------------------
print("\n💾 Saving model files...\n")

joblib.dump(model, MODEL_OUT)
joblib.dump(scaler, SCALER_OUT)
joblib.dump(encoder, ENCODER_OUT)

print("✔ Model saved:", MODEL_OUT)
print("✔ Scaler saved:", SCALER_OUT)
print("✔ Encoder saved:", ENCODER_OUT)

print("\n🎉 Model-3 Training Complete!\n")
