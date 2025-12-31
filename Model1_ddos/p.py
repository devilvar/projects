import json
import os
import sys

# Configuration
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(CURRENT_DIR, "Train_data.json")

OLD_LABEL = "Teardown_Attack"
NEW_LABEL = "Teardrop_Attack"

def rename_labels():
    print(f"📂 Processing file: {DATA_FILE}")

    if not os.path.exists(DATA_FILE):
        print(f"❌ Error: File '{DATA_FILE}' not found.")
        sys.exit(1)

    try:
        with open(DATA_FILE, 'r') as f:
            data = json.load(f)
            
        if not isinstance(data, list):
            print("❌ Error: JSON file does not contain a list.")
            sys.exit(1)

        count = 0
        for entry in data:
            if entry.get("label") == OLD_LABEL:
                entry["label"] = NEW_LABEL
                count += 1
        
        if count > 0:
            with open(DATA_FILE, 'w') as f:
                json.dump(data, f, indent=4)
            print(f"✅ Success! Renamed {count} labels from '{OLD_LABEL}' to '{NEW_LABEL}'.")
        else:
            print(f"ℹ️  No labels found matching '{OLD_LABEL}'. Nothing changed.")

    except json.JSONDecodeError:
        print("❌ Error: Invalid JSON file.")
    except Exception as e:
        print(f"❌ Unexpected Error: {e}")

if __name__ == "__main__":
    rename_labels()
