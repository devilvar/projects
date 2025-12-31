#!/usr/bin/env python3
import scapy.all as scapy
from datetime import datetime
import os
import threading
import time

# ------------------------------------------------------------
# PATH SETUP
# ------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "../Basic_data/logs")

os.makedirs(LOG_DIR, exist_ok=True)

# ------------------------------------------------------------
# FILE SETUP
# ------------------------------------------------------------

TIMESTAMP = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
PCAP_FILE = os.path.join(LOG_DIR, f"{TIMESTAMP}.pcap")

# ------------------------------------------------------------
# GLOBAL STATE
# ------------------------------------------------------------

packet_buffer = []
buffer_lock = threading.Lock()
FLUSH_INTERVAL = 5  # seconds

# ------------------------------------------------------------
# PACKET HANDLER
# ------------------------------------------------------------

def process_packet(packet):
    """
    Capture EVERY packet and store in buffer
    """
    with buffer_lock:
        packet_buffer.append(packet)

# ------------------------------------------------------------
# PERIODIC PCAP FLUSH
# ------------------------------------------------------------

def flush_pcap():
    """
    Periodically write packets to disk
    Prevents RAM overflow
    """
    while True:
        time.sleep(FLUSH_INTERVAL)
        with buffer_lock:
            if packet_buffer:
                scapy.wrpcap(PCAP_FILE, packet_buffer, append=True)
                packet_buffer.clear()

# ------------------------------------------------------------
# MAIN
# ------------------------------------------------------------

if __name__ == "__main__":
    print("Full Packet Capture Started")
    print(f"Interface : eth0")
    print(f"PCAP File : {PCAP_FILE}")
    print("Capturing ALL packets (no filters)...")
    print("Press Ctrl+C to stop\n")

    flush_thread = threading.Thread(target=flush_pcap, daemon=True)
    flush_thread.start()

    try:
        scapy.sniff(
            iface="eth0",
            store=False,
            prn=process_packet
        )
    except KeyboardInterrupt:
        print("\nCapture stopped by user")

    finally:
        # Final flush
        with buffer_lock:
            if packet_buffer:
                scapy.wrpcap(PCAP_FILE, packet_buffer, append=True)
                packet_buffer.clear()

        print("PCAP saved successfully")
        print(f"File: {PCAP_FILE}")
