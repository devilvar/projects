#!/usr/bin/env python3
import sys
import os
import time
import subprocess
import threading                      # ✅ ADDED
from RPLCD.i2c import CharLCD

# ================= PATH SETUP =================

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "Basic_Functions"))

# ================= CONFIG =================

LCD_ADDR = 0x27
COLS = 16
ROWS = 2
IFACE = "eth0"

LCD_ALERT_FILE = "/dev/shm/nids_lcd_alert.txt"

SCRIPTS = [
    ("ARP Engine", os.path.join(CURRENT_DIR, "ARP_cluster.py")),
    ("DDoS Engine", os.path.join(CURRENT_DIR, "subCluster1.py")),
    ("RealTime Eng", os.path.join(CURRENT_DIR, "subCluster2.py")),
    ("WiFi Sensor", os.path.join(CURRENT_DIR, "esp_controller.py")),
]

# ================= GLOBAL STATE =================

processes = {}
lcd = None
running = True

last_lcd_1 = ""
last_lcd_2 = ""

# ================= NETWORK =================

def set_promisc():
    try:
        out = subprocess.check_output(f"ip link show {IFACE}", shell=True).decode()
        if "PROMISC" not in out:
            subprocess.run(
                f"sudo ip link set {IFACE} promisc on",
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    except:
        pass

def has_internet():
    try:
        subprocess.check_call(
            ["ping", "-c", "1", "-W", "1", "8.8.8.8"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except:
        return False

# ================= LCD =================

def init_lcd():
    global lcd
    try:
        lcd = CharLCD(
            i2c_expander="PCF8574",
            address=LCD_ADDR,
            port=1,
            cols=COLS,
            rows=ROWS,
            charmap="A02",
            auto_linebreaks=False
        )
        lcd.clear()
        time.sleep(0.2)
        print("LCD Initialized")
    except Exception as e:
        print(f"LCD Init Failed: {e}")
        lcd = None

def sanitize(text):
    return "".join(c if 32 <= ord(c) <= 126 else " " for c in text)

def lcd_print(line1="", line2=""):
    global last_lcd_1, last_lcd_2

    if not lcd:
        return

    line1 = sanitize(line1).ljust(COLS)[:COLS]
    line2 = sanitize(line2).ljust(COLS)[:COLS]

    if line1 == last_lcd_1 and line2 == last_lcd_2:
        return

    try:
        lcd.cursor_pos = (0, 0)
        lcd.write_string(line1)

        lcd.cursor_pos = (1, 0)
        lcd.write_string(line2)

        time.sleep(0.05)

        last_lcd_1 = line1
        last_lcd_2 = line2
    except Exception as e:
        print(f"LCD write error: {e}")

# ================= PROCESS CONTROL =================

def launch_subsystems():
    print("\nLaunching subsystems\n")
    for name, path in SCRIPTS:
        try:
            p = subprocess.Popen(["python3", path], cwd=PROJECT_ROOT)
            processes[name] = p
            print(f"  {name} started (PID {p.pid})")
        except Exception as e:
            print(f"  {name} failed: {e}")

# ================= WEB DASHBOARD =================
# ✅ ADDED (threaded, non-blocking, isolated)

def start_web_dashboard():
    try:
        dashboard_path = os.path.join(PROJECT_ROOT,"web_dashboard", "app.py")
        if os.path.exists(dashboard_path):
            print("Starting Web Dashboard...")
            subprocess.Popen(
                ["python3", dashboard_path],
                cwd=os.path.dirname(dashboard_path),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        else:
            print("Web Dashboard not found")
    except Exception as e:
        print(f"Web Dashboard failed: {e}")

# ================= SHUTDOWN =================

def shutdown_all():
    print("\nGraceful shutdown")

    for name, p in processes.items():
        print(f"Stopping {name}")
        p.terminate()
        try:
            p.wait(timeout=5)
            print(f"{name} stopped")
        except subprocess.TimeoutExpired:
            print(f"Killing {name}")
            p.kill()
        time.sleep(0.5)

    if lcd:
        lcd_print("System", "OFF")
        time.sleep(1)
        lcd.close(clear=True)

# ================= MAIN LOOP =================

def monitor_loop():
    global last_lcd_1, last_lcd_2

    while running:
        try:
            if os.path.exists(LCD_ALERT_FILE):
                try:
                    with open(LCD_ALERT_FILE, "r") as f:
                        alert_text = f.read().strip()

                    lines = alert_text.split("\n", 1)
                    lcd_print(
                        lines[0] if lines else "ALERT",
                        lines[1] if len(lines) > 1 else ""
                    )

                    time.sleep(10)
                    os.remove(LCD_ALERT_FILE)
                    last_lcd_1 = ""
                    last_lcd_2 = ""
                except:
                    pass
            else:
                status = "NORMAL" if has_internet() else "NO NET"
                lcd_print(f"Status:{status}", "PROMISC:ON")

            time.sleep(5)

        except KeyboardInterrupt:
            break
        except:
            time.sleep(1)

# ================= MAIN =================

def main():
    global running

    init_lcd()
    set_promisc()

    lcd_print("Hello Friend", "System Booting")
    time.sleep(3)

    lcd_print("Loading Models", "Please Wait")
    launch_subsystems()

    # ✅ START WEB DASHBOARD IN BACKGROUND
    dashboard_thread = threading.Thread(
        target=start_web_dashboard,
        daemon=True
    )
    dashboard_thread.start()

    time.sleep(3)

    try:
        monitor_loop()
    finally:
        running = False
        shutdown_all()

if __name__ == "__main__":
    main()
