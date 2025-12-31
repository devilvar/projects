import os
import pandas as pd
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATASET_PATH = os.path.join(BASE_DIR, "Train_data.json")
MODEL_OUTPUT_PATH = os.path.join(BASE_DIR, "ddos_detection_model.pkl")
ENCODER_OUTPUT_PATH = os.path.join(BASE_DIR, "label_encoder.pkl")
FEATURES_OUTPUT_PATH = os.path.join(BASE_DIR, "feature_order.pkl")
FEATURE_IMG_PATH = os.path.join(BASE_DIR, "feature_importances3.png")
CONFUSION_IMG_PATH = os.path.join(BASE_DIR, "confusion_matrix2.png")

def train_model():

    print(f"Loading dataset: {DATASET_PATH}")

    try:
        df = pd.read_json(DATASET_PATH)
        print(f"Loaded dataset. Shape: {df.shape}")
    except Exception as e:
        print(f"ERROR loading dataset: {e}")
        return

    print("\nPreprocessing...")

    X = df.drop("label", axis=1)
    y = df["label"]

    encoder = LabelEncoder()
    y_encoded = encoder.fit_transform(y)
    print("Label encoding complete.")

    print("\nSplitting training/testing sets...")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )

    print(f"Train size: {len(X_train)}")
    print(f"Test size:  {len(X_test)}")

    print("\nTraining RandomForest model...")
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)
    print("Training complete.")

    print("\nEvaluating model...")
    y_pred = model.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nAccuracy: {accuracy:.4f} ({accuracy:.2%})")

    y_test_labels = encoder.inverse_transform(y_test)
    y_pred_labels = encoder.inverse_transform(y_pred)

    print("\nClassification Report:")
    print(classification_report(y_test_labels, y_pred_labels, zero_division=0))

    print("\nGenerating Confusion Matrix...")
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=encoder.classes_,
                yticklabels=encoder.classes_)
    plt.title("Confusion Matrix")
    plt.xlabel("Predicted Label")
    plt.ylabel("Actual Label")
    plt.tight_layout()
    plt.savefig(CONFUSION_IMG_PATH)
    print(f"Confusion Matrix plot saved to: {CONFUSION_IMG_PATH}")

    print("\nTop 10 Feature Importances:")
    importances = pd.Series(model.feature_importances_, index=X.columns)
    top_10 = importances.nlargest(10)
    print(top_10)

    plt.figure(figsize=(10, 7))
    top_10.sort_values().plot(kind="barh")
    plt.title("Top 10 Feature Importances")
    plt.xlabel("Importance")
    plt.tight_layout()
    plt.savefig(FEATURE_IMG_PATH)
    print(f"Feature importance plot saved to: {FEATURE_IMG_PATH}")

    print("\nSaving model files...")
    joblib.dump(model, MODEL_OUTPUT_PATH)
    joblib.dump(encoder, ENCODER_OUTPUT_PATH)
    joblib.dump(list(X.columns), FEATURES_OUTPUT_PATH)

    print(f"Model saved to: {MODEL_OUTPUT_PATH}")
    print(f"Encoder saved to: {ENCODER_OUTPUT_PATH}")
    print(f"Feature list saved to: {FEATURES_OUTPUT_PATH}")

    print("\nModel-1 Training Complete!")

if __name__ == "__main__":
    train_model()
