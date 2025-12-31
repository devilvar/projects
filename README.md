# IoT && AI -Based Network Intrusion Detection System (NIDS) with Active Response

## 📌 Project Overview
This project is a lightweight, embedded Network Intrusion Detection System (NIDS) built on the Raspberry Pi. Unlike traditional passive systems that only log threats, this system is designed to detect network anomalies using Machine Learning and perform **active responses** (such as deauthentication or firewall blocking) to neutralize threats in real-time.

---

## ❓ Why I Do This (Motivation)
With the rapid expansion of Internet of Things (IoT) devices, home and small office networks are becoming increasingly vulnerable.
* **The Problem:** Most standard routers lack sophisticated inspection capabilities. Dedicated security appliances are expensive, power-hungry, and complex to configure.
* **The Goal:** To democratize network security by creating a low-cost, portable, and intelligent defense system that runs on accessible hardware (Raspberry Pi) while providing enterprise-level detection capabilities through Machine Learning.

---

## ⚠️ The Loophole (Current Limitations in Existing Solutions)
Existing security solutions often suffer from specific "loopholes" that this project aims to address:

1.  **Passive Monitoring:** Most traditional IDSs are passive; they alert the administrator but do nothing to stop the attack. By the time the admin sees the log, the data exfiltration has often already occurred.
2.  **Signature-Based Reliance:** Many systems rely on databases of known attack signatures. They fail to detect "Zero-Day" attacks or novel anomalies that don't match a pre-existing pattern.
3.  **Resource Intensity:** AI-driven security usually requires heavy GPU/CPU power, making it unsuitable for edge devices or battery-powered setups.
4.  **Lack of Visibility:** Standard consumer routers provide little to no visualization of what is actually happening on the network layer (e.g., ARP spoofing attempts).

---

## 🎯 Project Scope
This system is designed for **Edge Security**—protecting the network at the entry point or within the local LAN.

* **Traffic Acquisition:** Capturing live network packets using the Raspberry Pi's network interface (promiscuous mode).
* **Data Processing:** Feature extraction from packets (Protocol, Flag, Size, Frequency) suitable for ML analysis.
* **Detection Engine:** Utilizing Machine Learning algorithms to classify traffic as "Benign" or "Malicious" (DoS, Probe, U2R, R2L).
* **Visualization:** Real-time status updates via an attached LCD display for immediate physical feedback.
* **Hardware Target:** Optimized for Raspberry Pi 4/5 (ARM architecture).

---

## 💡 What I Propose (The Solution)
I propose an **Active Defense System** that closes the loop between detection and action.

### 1. Intelligent Detection
Instead of static rules, this project uses a Machine Learning model (trained on datasets like NSL-KDD or custom captured traffic) to identify abnormal traffic patterns. This allows the detection of previously unknown attacks based on behavior rather than signatures.

### 2. Active Response Mechanism
Upon detecting a high-confidence threat, the system does not just log it. It triggers an **Active Response Module** which:
* Identifies the attacker's MAC/IP address.
* Initiates a counter-measure (e.g., sending Deauthentication frames to disconnect the attacker or updating `iptables` to drop packets).
* **Note:** This feature transforms the system from a passive NIDS into an active IPS (Intrusion Prevention System).

### 3. Hardware Integration
The system integrates with hardware components (like an I2C LCD display) to show:
* Current System Health (CPU/RAM).
* Real-time Attack Alerts.
* Network Traffic stats.

---

## 🛠️ Technology Stack
* **Hardware:** Raspberry Pi, I2C LCD Display.
* **Language:** Python 3.
* **Libraries:** Scapy (Packet sniffing), Pandas/NumPy (Data processing), Scikit-Learn (Machine Learning), RPi.GPIO (Hardware control).
* **Protocols:** TCP/IP, UDP, ICMP, ARP.

## 🚀 Future Enhancements
* Integration with a centralized dashboard (Web UI).
* Support for Deep Learning models (CNN/RNN) for packet payload analysis.
* Email/SMS notification integration.

---

### ⚖️ Disclaimer
*This tool is for educational purposes and for protecting your own network. Using active response mechanisms (like deauthentication) on networks you do not own is illegal. The author is not responsible for misuse.*
