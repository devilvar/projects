#!/usr/bin/env python3
import sys
import os
from threading import Thread
from queue import Queue
from scapy.all import sniff

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
sys.path.insert(0, BASE_DIR)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "Basic_Functions"))

import dns_tunnel
import DHCP_attacks
import DNS_IP_Spoofing
import policy_violation
import c2_botnet
import NTP_attack
import IAM  

IFACE = "eth0"

# ================= QUEUE CONFIG =================

DNS_QUEUE_SIZE = 1000
DHCP_QUEUE_SIZE = 1000
SPOOF_QUEUE_SIZE = 1000
POLICY_QUEUE_SIZE = 1000
C2_QUEUE_SIZE = 1000
NTP_QUEUE_SIZE = 1000
IAM_QUEUE_SIZE = 1000   

DNS_WORKERS = 1
DHCP_WORKERS = 1
SPOOF_WORKERS = 1
POLICY_WORKERS = 1
C2_WORKERS = 1
NTP_WORKERS = 1
IAM_WORKERS = 1        

dns_queue = Queue(maxsize=DNS_QUEUE_SIZE)
dhcp_queue = Queue(maxsize=DHCP_QUEUE_SIZE)
spoof_queue = Queue(maxsize=SPOOF_QUEUE_SIZE)
policy_queue = Queue(maxsize=POLICY_QUEUE_SIZE)
c2_queue = Queue(maxsize=C2_QUEUE_SIZE)
ntp_queue = Queue(maxsize=NTP_QUEUE_SIZE)
iam_queue = Queue(maxsize=IAM_QUEUE_SIZE)   

# ================= WORKERS =================

def dns_worker():
    while True:
        pkt = dns_queue.get()
        if pkt is None:
            dns_queue.task_done()
            break
        try:
            dns_tunnel.detect_tunneling(pkt)
        except:
            pass
        dns_queue.task_done()

def dhcp_worker():
    while True:
        pkt = dhcp_queue.get()
        if pkt is None:
            dhcp_queue.task_done()
            break
        try:
            DHCP_attacks.detect_dhcp_attacks(pkt)
        except:
            pass
        dhcp_queue.task_done()

def spoof_worker():
    while True:
        pkt = spoof_queue.get()
        if pkt is None:
            spoof_queue.task_done()
            break
        try:
            DNS_IP_Spoofing.process_packet(pkt)
        except:
            pass
        spoof_queue.task_done()

def policy_worker():
    while True:
        pkt = policy_queue.get()
        if pkt is None:
            policy_queue.task_done()
            break
        try:
            policy_violation.process_packet(pkt)
        except:
            pass
        policy_queue.task_done()

def c2_worker():
    while True:
        pkt = c2_queue.get()
        if pkt is None:
            c2_queue.task_done()
            break
        try:
            c2_botnet.process_packet(pkt)
        except:
            pass
        c2_queue.task_done()

def ntp_worker():
    while True:
        pkt = ntp_queue.get()
        if pkt is None:
            ntp_queue.task_done()
            break
        try:
            NTP_attack.process_packet(pkt)
        except:
            pass
        ntp_queue.task_done()

# ✅ IAM WORKER
def iam_worker():
    while True:
        pkt = iam_queue.get()
        if pkt is None:
            iam_queue.task_done()
            break
        try:
            IAM.process_packet(pkt)
        except:
            pass
        iam_queue.task_done()

# ================= PACKET HANDLER =================

def packet_handler(pkt):
    for q in (
        dns_queue,
        dhcp_queue,
        spoof_queue,
        policy_queue,
        c2_queue,
        ntp_queue,
        iam_queue, 
    ):
        try:
            q.put_nowait(pkt)
        except:
            pass

# ================= MAIN =================

def main():
    print("SUB-CLUSTER 2 STARTED ON", IFACE)
    print("Active Modules:")
    print(" - DNS Tunneling Detection")
    print(" - DHCP Attack Detection")
    print(" - DNS & IP Spoofing Detection")
    print(" - Policy Violation Detection")
    print(" - C2 Botnet Beaconing Detection")
    print(" - NTP Amplification Detection")
    print(" - IAM / User & Web Policy Engine") 
    print("-" * 60)

    workers = []

    for target, name, count in [
        (dns_worker, "DNS", DNS_WORKERS),
        (dhcp_worker, "DHCP", DHCP_WORKERS),
        (spoof_worker, "SPOOF", SPOOF_WORKERS),
        (policy_worker, "POLICY", POLICY_WORKERS),
        (c2_worker, "C2", C2_WORKERS),
        (ntp_worker, "NTP", NTP_WORKERS),
        (iam_worker, "IAM", IAM_WORKERS),   
    ]:
        for i in range(count):
            t = Thread(
                target=target,
                daemon=True,
                name=f"{name}-Worker-{i+1}"
            )
            t.start()
            workers.append(t)
            print("Started", t.name)

    print("-" * 60)

    try:
        sniff(iface=IFACE, prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("\nShutting down Sub-Cluster 2")

        for q, n in [
            (dns_queue, DNS_WORKERS),
            (dhcp_queue, DHCP_WORKERS),
            (spoof_queue, SPOOF_WORKERS),
            (policy_queue, POLICY_WORKERS),
            (c2_queue, C2_WORKERS),
            (ntp_queue, NTP_WORKERS),
            (iam_queue, IAM_WORKERS), 
        ]:
            for _ in range(n):
                q.put(None)

        for t in workers:
            t.join(timeout=2)

        print("Sub-Cluster 2 stopped")

if __name__ == "__main__":
    main()
