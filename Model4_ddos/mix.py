import json
import os
import random

DATA_DIR = "DATA"
NORMAL_FILE = os.path.join(DATA_DIR, "Normal.json")
MIXED_FILE = os.path.join(DATA_DIR, "Mixed_Attack.json")
OUTPUT_FILE = os.path.join(DATA_DIR, "Final_Mixed_Verifier_Dataset.json")

def load_json_list(path):
    if not os.path.exists(path):
        print(f"[ERROR] File not found: {path}")
        return []

    try:
        with open(path, "r") as f:
            data = json.load(f)
            if not isinstance(data, list):
                print(f"[ERROR] File does not contain a JSON list: {path}")
                return []
            return data
    except Exception as e:
        print(f"[ERROR] Cannot read {path}: {e}")
        return []


def main():
    print("\nLoading dataset blocks...")

    normal_data = load_json_list(NORMAL_FILE)
    mixed_data = load_json_list(MIXED_FILE)

    if not normal_data and not mixed_data:
        print("\n[ERROR] No dataset files found or both files are empty.")
        return

    print(f"Loaded Normal blocks: {len(normal_data)}")
    print(f"Loaded Mixed_Attack blocks: {len(mixed_data)}")

    # Merge
    combined = normal_data + mixed_data

    # Shuffle
    random.shuffle(combined)

    print(f"Total combined blocks: {len(combined)}")

    # Save final dataset
    with open(OUTPUT_FILE, "w") as f:
        json.dump(combined, f, indent=4)

    print(f"\n[OK] Final merged dataset saved at:")
    print(f"     {OUTPUT_FILE}")

    # Delete original files
    try:
        if os.path.exists(NORMAL_FILE):
            os.remove(NORMAL_FILE)
        if os.path.exists(MIXED_FILE):
            os.remove(MIXED_FILE)
        print("\nPrevious files deleted:")
        print(f"  - {NORMAL_FILE}")
        print(f"  - {MIXED_FILE}")
    except Exception as e:
        print(f"[ERROR] Could not delete original files: {e}")

    print("\nCompleted successfully.\n")


if __name__ == "__main__":
    main()
