import smtplib
from email.message import EmailMessage
import requests
import time
import os
import json

# ================= EMAIL CONFIG =================

EMAIL_ADDRESS = "Uses_your_mail"
EMAIL_APP_PASSWORD = "***********"
EMAIL_RECEIVER = "varunkumarvenigalla@gmail.com"

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465

# ================= TELEGRAM CONFIG =================

TELEGRAM_BOT_TOKEN = "Use_your_api"
TELEGRAM_CHAT_ID = "Use_your_id"

# ================= LCD CONFIG =================

LCD_ALERT_FILE = "/dev/shm/nids_lcd_alert.txt"
LCD_ALERT_MESSAGE = "ATTACK DETECTED\nCheck Web Panel"

# ================= ALERT STORAGE =================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JSON_DIR = os.path.join(BASE_DIR, "Basic_data", "logs")
ALERTS_JSON = os.path.join(JSON_DIR, "alerts.json")

os.makedirs(JSON_DIR, exist_ok=True)

# ================= RATE LIMITING =================

ALERT_COOLDOWN_SECONDS = 90
last_alert_times = {}

# ================= INTERNAL HELPERS =================

def _load_alerts():
    if not os.path.exists(ALERTS_JSON):
        return []
    try:
        with open(ALERTS_JSON, "r") as f:
            return json.load(f)
    except:
        return []

def _save_alert(alert_entry):
    alerts = _load_alerts()
    alerts.append(alert_entry)
    try:
        with open(ALERTS_JSON, "w") as f:
            json.dump(alerts, f, indent=4)
    except Exception as e:
        print(f"❌ Failed to write alerts.json: {e}")

# ================= ALERT CHANNELS =================

def _send_email_alert(subject, body):
    try:
        msg = EmailMessage()
        msg.set_content(body)
        msg["Subject"] = subject
        msg["From"] = EMAIL_ADDRESS
        msg["To"] = EMAIL_RECEIVER

        print("... sending email alert via Gmail ...")
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_APP_PASSWORD)
            smtp.send_message(msg)
        print("************** Email alert sent **************")
    except Exception as e:
        print(f"❌ Email alert failed: {e}")

def _send_telegram_alert(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message}

    try:
        print("... sending Telegram alert ...")
        response = requests.post(url, data=payload, timeout=20)
        if response.status_code == 200:
            print("************** Telegram alert sent **************")
        else:
            print(f"❌ Telegram failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Telegram alert failed: {e}")

def _send_lcd_alert():
    try:
        with open(LCD_ALERT_FILE, "w") as f:
            f.write(LCD_ALERT_MESSAGE)
        print("📟 LCD alert triggered")
    except Exception as e:
        print(f"❌ LCD alert failed: {e}")

# ================= PUBLIC FUNCTION =================

def trigger_alert(attack_type, timestamp, source_info=None, details_dict=None):
    """
    Main alert trigger used by detection modules.
    """

    global last_alert_times
    current_time = time.time()

    last_time = last_alert_times.get(attack_type, 0)
    if current_time - last_time < ALERT_COOLDOWN_SECONDS:
        print(f"[{timestamp}] Cooldown active for '{attack_type}'. No new alert sent.")
        return

    print(f"[{timestamp}] Triggering alert for '{attack_type}'...")

    # -------- Store alert to alerts.json --------
    alert_entry = {
        "timestamp": timestamp,
        "attack_type": attack_type,
        "source_info": source_info,
        "details": details_dict or {}
    }
    _save_alert(alert_entry)

    # -------- Build message --------
    subject = f"SECURITY ALERT: {attack_type}"
    body = (
        f"A potential security threat has been detected.\n\n"
        f"Timestamp: {timestamp}\n"
        f"Attack Type: {attack_type}\n"
    )

    if source_info:
        body += f"Source Info: {source_info}\n"

    if details_dict:
        body += "\n--- Indicators ---\n"
        for k, v in details_dict.items():
            body += f"{k.replace('_',' ').title()}: {v}\n"

    # -------- Send alerts --------
    _send_lcd_alert()
    _send_telegram_alert(body)
    _send_email_alert(subject, body)

    last_alert_times[attack_type] = current_time
