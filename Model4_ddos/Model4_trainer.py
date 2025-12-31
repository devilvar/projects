#!/usr/bin/env python3
import json
import os

import numpy as np
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
    roc_auc_score,
    roc_curve
)

import matplotlib
matplotlib.use("Agg")  # For headless environments (Raspberry Pi)
import matplotlib.pyplot as plt

DATA_FILE = "Model4_data.json"

MODEL_FILE = "model4_model.pkl"
SCALER_FILE = "model4_scaler.pkl"
ENCODER_FILE = "model4_label_encoder.pkl"
FEATURE_ORDER_FILE = "feature_order_model4.json"

FEATURE_IMPORTANCE_PNG = "model4_feature_importances.png"
CONFUSION_MATRIX_PNG = "model4_confusion_matrix.png"
ROC_CURVE_PNG = "model4_roc_curve.png"


def load_dataset(path: str) -> pd.DataFrame:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Dataset file not found: {path}")

    with open(path, "r") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("Model4_data.json must contain a JSON list of objects")

    df = pd.DataFrame(data)
    return df


def main():
    print("[*] Loading dataset...")
    df = load_dataset(DATA_FILE)
    print(f"    Loaded {len(df)} samples")

    if "label" not in df.columns:
        raise ValueError("Dataset must contain a 'label' field")

    # Separate features and labels
    y = df["label"]
    X = df.drop(columns=["label"])

    # Save feature order for inference
    feature_order = list(X.columns)
    with open(FEATURE_ORDER_FILE, "w") as f:
        json.dump(feature_order, f, indent=4)
    print(f"[*] Saved feature order -> {FEATURE_ORDER_FILE}")

    # Label encode y
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    joblib.dump(le, ENCODER_FILE)
    print(f"[*] Saved label encoder -> {ENCODER_FILE}")
    print(f"    Classes: {list(le.classes_)} (encoded as {list(range(len(le.classes_)))} )")

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded,
        test_size=0.2,
        random_state=42,
        stratify=y_encoded
    )

    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    joblib.dump(scaler, SCALER_FILE)
    print(f"[*] Saved scaler -> {SCALER_FILE}")

    # Model definition (verification model)
    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=16,
        min_samples_split=4,
        min_samples_leaf=2,
        n_jobs=-1,
        random_state=42
    )

    print("[*] Training RandomForest (Model 4 verification model)...")
    model.fit(X_train_scaled, y_train)
    joblib.dump(model, MODEL_FILE)
    print(f"[*] Saved model -> {MODEL_FILE}")

    # Evaluation
    print("[*] Evaluating...")
    y_pred = model.predict(X_test_scaled)

    print("\n=== Classification report (Model 4) ===")
    print(classification_report(y_test, y_pred, target_names=le.classes_))

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred, normalize="true")
    disp = ConfusionMatrixDisplay(
        confusion_matrix=cm,
        display_labels=le.classes_
    )
    fig_cm, ax_cm = plt.subplots(figsize=(5, 4))
    disp.plot(ax=ax_cm, cmap="Blues", colorbar=False)
    ax_cm.set_title("Model 4 - Normalized Confusion Matrix")
    plt.tight_layout()
    fig_cm.savefig(CONFUSION_MATRIX_PNG, dpi=150)
    plt.close(fig_cm)
    print(f"[*] Saved confusion matrix -> {CONFUSION_MATRIX_PNG}")

    # Feature importances
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]  # descending
    sorted_features = [feature_order[i] for i in indices]
    sorted_importances = importances[indices]

    fig_fi, ax_fi = plt.subplots(figsize=(8, 5))
    ax_fi.bar(range(len(sorted_importances)), sorted_importances)
    ax_fi.set_xticks(range(len(sorted_importances)))
    ax_fi.set_xticklabels(sorted_features, rotation=45, ha="right")
    ax_fi.set_ylabel("Importance")
    ax_fi.set_title("Model 4 - Feature Importances (RandomForest)")
    plt.tight_layout()
    fig_fi.savefig(FEATURE_IMPORTANCE_PNG, dpi=150)
    plt.close(fig_fi)
    print(f"[*] Saved feature importances -> {FEATURE_IMPORTANCE_PNG}")

    # ROC curve (only if binary classification)
    if len(le.classes_) == 2:
        if hasattr(model, "predict_proba"):
            y_score = model.predict_proba(X_test_scaled)[:, 1]
            auc = roc_auc_score(y_test, y_score)
            fpr, tpr, _ = roc_curve(y_test, y_score)

            fig_roc, ax_roc = plt.subplots(figsize=(5, 4))
            ax_roc.plot(fpr, tpr, label=f"ROC curve (AUC = {auc:.3f})")
            ax_roc.plot([0, 1], [0, 1], linestyle="--")
            ax_roc.set_xlabel("False Positive Rate")
            ax_roc.set_ylabel("True Positive Rate")
            ax_roc.set_title("Model 4 - ROC Curve")
            ax_roc.legend(loc="lower right")
            plt.tight_layout()
            fig_roc.savefig(ROC_CURVE_PNG, dpi=150)
            plt.close(fig_roc)
            print(f"[*] Saved ROC curve -> {ROC_CURVE_PNG}")
        else:
            print("[!] Model has no predict_proba; skipping ROC curve.")
    else:
        print("[!] More than 2 classes; ROC curve skipped.")

    print("\n[*] Training complete. Model 4 (verification model) is ready.")


if __name__ == "__main__":
    main()
