import os
import json
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib

# ------------------------------------------------------------
# PATH SETUP (UPDATED FOR NEW DIRECTORY STRUCTURE)
# ------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATA_PATH = os.path.join(BASE_DIR, "model2_data.json")
MODEL_OUT = os.path.join(BASE_DIR, "model2_model.pkl")
SCALER_OUT = os.path.join(BASE_DIR, "model2_scaler.pkl")
ENCODER_OUT = os.path.join(BASE_DIR, "model2_label_encoder.pkl")

# ------------------------------------------------------------
# LOAD DATASET
# ------------------------------------------------------------

print("📥 Loading dataset:", DATA_PATH)

try:
    with open(DATA_PATH, "r") as f:
        data = json.load(f)
except Exception as e:
    print(f"❌ ERROR: Unable to read dataset. Details: {e}")
    exit(1)

df = pd.DataFrame(data)
print(f"✔ Loaded {len(df)} samples.\n")

# ------------------------------------------------------------
# VALIDATION
# ------------------------------------------------------------

if "label" not in df.columns:
    print("❌ ERROR: 'label' column missing. Please label dataset first.")
    exit(1)

df = df.dropna()

# ------------------------------------------------------------
# SPLIT FEATURES & LABEL
# ------------------------------------------------------------

y = df["label"]
X = df.drop(columns=["label"])

print("Feature count:", len(X.columns))
print("Label count:", len(y.unique()))
print("\nLabels:", y.unique(), "\n")

# ------------------------------------------------------------
# LABEL ENCODER
# ------------------------------------------------------------

encoder = LabelEncoder()
y_encoded = encoder.fit_transform(y)

# ------------------------------------------------------------
# FEATURE SCALING
# ------------------------------------------------------------

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# ------------------------------------------------------------
# TRAIN-TEST SPLIT
# ------------------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)

print("Training samples:", len(X_train))
print("Testing samples:", len(X_test), "\n")

# ------------------------------------------------------------
# TRAIN MODEL
# ------------------------------------------------------------

print("🧠 Training RandomForest model...\n")

model = RandomForestClassifier(
    n_estimators=400,
    max_depth=20,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

# ------------------------------------------------------------
# EVALUATE MODEL
# ------------------------------------------------------------

y_pred = model.predict(X_test)

acc = accuracy_score(y_test, y_pred)
print("✔ Accuracy:", acc)
print("\n📊 Classification Report:\n")
print(classification_report(y_test, y_pred, target_names=encoder.classes_))

# ------------------------------------------------------------
# SAVE MODEL + SCALER + ENCODER
# ------------------------------------------------------------

print("\n💾 Saving model files...\n")

joblib.dump(model, MODEL_OUT)
joblib.dump(scaler, SCALER_OUT)
joblib.dump(encoder, ENCODER_OUT)

print("✔ Model saved to:", MODEL_OUT)
print("✔ Scaler saved to:", SCALER_OUT)
print("✔ Encoder saved to:", ENCODER_OUT)
print("\n🎉 MODEL-2 TRAINING COMPLETE!\n")
