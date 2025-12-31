#!/usr/bin/env python3
import serial
import time
import sys
import os
import json
from datetime import datetime

# --- Path Setup ---
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
sys.path.append(os.path.join(PROJECT_ROOT, "Basic_Functions"))

try:
    import alerter
except ImportError:
    class _Fake:
        @staticmethod
        def trigger_alert(a, b, c, d): print(f"[ALERT] {a} {d}")
    alerter = _Fake()

# --- CONFIGURATION ---
# USB Serial Port (Usually /dev/ttyUSB0 or /dev/ttyACM0)
SERIAL_PORT = "/dev/ttyUSB0" 
BAUD_RATE = 9600
CONFIG_FILE = os.path.join(PROJECT_ROOT, "Basic_data", "JSON", "Router_details.json")

def ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def load_router_config():
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading router config: {e}")
        return None

def main():
    print(f"📡 WIRELESS CONTROLLER STARTED (USB Mode)")
    
    # 1. Load Config
    config = load_router_config()
    if not config:
        print("Config missing. Exiting.")
        sys.exit(1)
        
    ssid = config.get("ssid")
    bssid = config.get("bssid").lower()
    channel = config.get("channel", 6)
    
    print(f"   Target Network: {ssid} ({bssid}) Ch:{channel}")

    try:
        # Open USB Serial Connection
        ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1)
        time.sleep(2) 
        
        # 2. Send Configuration
        cfg_cmd = f"cmd:CONFIG|{ssid}|{bssid}|{channel}\n"
        print(f"   Sending Config to ESP8266...")
        ser.write(cfg_cmd.encode('utf-8'))
        time.sleep(1)
        
        # 3. Send Start Command
        print("   Activating Monitor Mode...")
        ser.write(b"cmd:START_MONITOR\n")
        
        # 4. Listen Loop
        print("  System Active. Listening for alerts...")
        
        while True:
            if ser.in_waiting > 0:
                try:
                    line = ser.readline().decode('utf-8').strip()
                    
                    if line.startswith("WIFI_ATTACK:"):
                        parts = line.split(":")
                        if len(parts) > 1:
                            payload = parts[1].split("|")
                            attack_type = payload[0]
                            extra_info = payload[1] if len(payload) > 1 else "N/A"
                            
                            print(f"\n WIRELESS ATTACK: {attack_type} ({extra_info})")
                            
                            alerter.trigger_alert(
                                f"Wireless_{attack_type}",
                                ts(),
                                "ESP8266 Sensor",
                                {"Details": extra_info}
                            )
                    
                    elif line.startswith("STATUS:"):
                        print(f"[SENSOR] {line.split(':')[1]}")
                        
                except Exception:
                    pass

    except serial.SerialException as e:
        print(f"Serial Error: Is the ESP plugged in? ({e})")
        print(f"   Check the port name: ls /dev/tty*")
    except KeyboardInterrupt:
        try:
            ser.write(b"cmd:STOP_MONITOR\n")
        except: pass
        print("\nStopped.")

if __name__ == "__main__":
    main()
