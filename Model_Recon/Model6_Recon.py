#!/usr/bin/env python3
import json
import pandas as pd
import numpy as np
import joblib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix
import seaborn as sns

DATA_FILE = "Train_data.json"
MODEL_FILE = "model6_recon.pkl"
SCALER_FILE = "scaler6_recon.pkl"
ENCODER_FILE = "encoder6_recon.pkl"
FEATURE_ORDER_FILE = "feature_order6_recon.json"
FI_PNG = "feature_importance.png"
CM_PNG = "confusion_matrix.png"

with open(DATA_FILE, "r") as f:
    data = json.load(f)

df = pd.DataFrame(data)
labels = df["label"]
df = df.drop(columns=["label"])

feature_order = list(df.columns)

encoder = LabelEncoder()
y = encoder.fit_transform(labels)

scaler = StandardScaler()
X = scaler.fit_transform(df)

model = RandomForestClassifier(
    n_estimators=300,
    max_depth=15,
    min_samples_split=4,
    min_samples_leaf=2,
    class_weight="balanced_subsample",
    random_state=42
)

model.fit(X, y)

joblib.dump(model, MODEL_FILE)
joblib.dump(scaler, SCALER_FILE)
joblib.dump(encoder, ENCODER_FILE)

with open(FEATURE_ORDER_FILE, "w") as f:
    json.dump(feature_order, f, indent=4)

importances = model.feature_importances_
indices = np.argsort(importances)[::-1]

plt.figure(figsize=(12,6))
plt.bar(range(len(importances)), importances[indices])
plt.xticks(range(len(importances)), [feature_order[i] for i in indices], rotation=90)
plt.tight_layout()
plt.savefig(FI_PNG)
plt.close()

y_pred = model.predict(X)
cm = confusion_matrix(y, y_pred)
plt.figure(figsize=(8,6))
sns.heatmap(cm, annot=True, fmt='d', cmap="Blues",
            xticklabels=encoder.classes_,
            yticklabels=encoder.classes_)
plt.tight_layout()
plt.savefig(CM_PNG)
plt.close()

print("Model trained and saved.")
