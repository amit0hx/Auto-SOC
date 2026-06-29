<div align="center">

# 🛡️ Auto-SOC

### Intelligent Network Intrusion Detection & Automated Incident Response

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.40+-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)](https://streamlit.io)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.5+-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![Google Gemini](https://img.shields.io/badge/Google_Gemini-2.5_Flash-4285F4?style=for-the-badge&logo=google&logoColor=white)](https://ai.google.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-00ff88?style=for-the-badge)](LICENSE)

**Version:** `2.0.0` &nbsp;|&nbsp; **Author:** [amit0hx](https://github.com/amit0hx) &nbsp;|&nbsp; **Status:** Active 
<br>

*A hybrid-AI Security Operations Center framework that combines ML-based anomaly detection with LLM-powered incident response automation.*

</div>

---

## 🔍 Overview

Auto-SOC bridges the gap between **raw network anomaly detection** and **actionable incident response**. It integrates three AI layers:

1. 🧠 A **Random Forest Classifier** analyzes network traffic logs and classifies each connection into **5 categories** (Normal + DoS, Probe, R2L, U2R)
2. 🔍 Each prediction is explained with **SHAP** — showing *why* a connection was flagged (not just a label)
3. 🤖 Detected threats are forwarded to **Google Gemini (LLM)** which generates technical **mitigation playbooks** with MITRE ATT&CK references
4. 📊 A **Streamlit Dashboard** provides real-time visualization, batch analysis, detection timeline, and an analyst feedback loop
5. 📡 A **real-world capture bridge** (`live_ids.py`) feeds **live Wireshark/tshark traffic** through the same pipeline and **identifies attack sources by IP** (reverse-DNS + threat-intelligence enrichment)

---

## ✨ Features

| Feature | Description |
|---|---|
| 🎯 **5 Attack Categories** | Normal, DoS, Probe, R2L, U2R — aligned with NSL-KDD standard |
| 📡 **10-Feature Dataset** | Duration, protocol, service, src/dst bytes, TCP flags, connection counts |
| 🖥️ **Dark SOC Dashboard** | Real-time stats, severity badges (CVSS), color-coded alerts |
| ⚡ **Batch Simulation** | Analyze 10 / 25 / 50 / 100 packets at once with progress tracking |
| 📈 **Model Intelligence** | Accuracy metrics, feature importance chart, confusion matrix, per-class F1 |
| 📋 **LLM Playbooks** | 4-point IR playbooks with MITRE ATT&CK references (online + offline mode) |
| 🔍 **SHAP Explainability** | Per-prediction "why flagged" — top feature contributions toward the detected class |
| 🔴 **Severity Mapping** | Automatic CRITICAL / HIGH / MEDIUM classification per attack type |
| 📈 **Detection Timeline** | Time-series view of detections (severity over time) |
| 🔁 **Analyst Feedback Loop** | Mark detections correct / false-positive — logged for future retraining |
| 📜 **Attack History** | Session-persistent log with timestamps, predictions, and match tracking |
| 📡 **Live Packet Capture** | Real traffic via Wireshark/Npcap — `.pcap`, scapy live, or real-time `tshark` feed (IPv4 + IPv6) |
| 🎯 **Attack Source ID** | Identifies attacker **source IP**, internal/external origin, reverse-DNS, and threat-intel reputation |
| 🌐 **Dashboard Live Capture** | Capture real packets from the dashboard — source-IP table + auto-generated IR playbook for the top attacker |

---

## 🏗️ Architecture

```
dataset_generator.py  →  network_logs.csv (10K synthetic logs)
         ↓
train_model.py        →  model.pkl + encoders.pkl + metrics.json + confusion_matrix.png
         ↓
app.py (Streamlit)    ←→  llm_engine.py (Gemini API / Mock)
         ↓
   Live SOC Dashboard
```

### 📂 File Breakdown

| File | Purpose |
|---|---|
| `dataset_generator.py` | Generates 10,000 synthetic network logs with 5 attack types |
| `train_model.py` | Trains Random Forest, exports model + confusion matrix + metrics JSON |
| `llm_engine.py` | Gemini API integration for automated IR playbooks (with offline fallback) |
| `app.py` | Streamlit dashboard — the main UI (synthetic simulation + live capture) |
| `live_ids.py` | Real-world bridge: Wireshark/tshark packets → features → model → playbook + attack-source report |
| `explain.py` | SHAP per-prediction explainability (with rule-based fallback) |
| `threat_intel.py` | IP reputation / threat-intelligence lookup (AbuseIPDB + offline fallback) |
| `make_demo_pcap.py` | Generates a demo `.pcap` (SYN flood + port scan) for Wireshark-free testing |
| `requirements.txt` | Python dependencies |
| `.env.example` | Template for API key configuration |

---

## 🚀 Setup & Run

### 1. Clone & Install
```bash
git clone https://github.com/amit0hx/Auto-SOC.git
cd Auto-SOC
pip install -r requirements.txt
```

### 2. (Optional) Configure Gemini API
```bash
cp .env.example .env
# Edit .env and add your Gemini API key
# Without API key, the system uses built-in mock playbooks
```

### 3. Generate Dataset & Train Model
```bash
python dataset_generator.py
python train_model.py
```

### 4. Launch Dashboard
```bash
streamlit run app.py
```
Open `http://localhost:8501` in your browser.

---

## 📡 Real-World Live Capture (Wireshark / tshark)

Test Auto-SOC on **real network traffic** instead of synthetic data. Requires
[Wireshark](https://www.wireshark.org/) (bundles the **Npcap** driver); `scapy` is in `requirements.txt`.

```bash
# List capture interfaces (note your Wi-Fi / Ethernet name)
python live_ids.py --list-ifaces

# Analyse a .pcap saved from Wireshark (no admin needed)
python live_ids.py --pcap demo_capture.pcap

# Real-time feed straight from Wireshark's tshark engine
python live_ids.py --tshark --iface Ethernet --timeout 20 --flush 5

# Live sniff via scapy (--no-playbook for fast verdicts)
python live_ids.py --live --iface Ethernet --count 200 --timeout 25
```

Each detected attack is attributed to a **source IP** with origin (internal/external) and
reverse-DNS, ranked into an **Attack Source Identification** report. The same capture is also
available inside the dashboard under **📡 Live Network Capture**. A bundled `demo_capture.pcap`
(SYN flood + port scan) lets you demo detection without installing Wireshark.

---

## ☁️ Running on Google Colab

```python
# Install
!pip install -r requirements.txt

# Generate & Train
!python dataset_generator.py
!python train_model.py

# Launch with tunnel
!streamlit run app.py &>/content/logs.txt &
!npx -y localtunnel --port 8501
```

---

## 🛠️ Tech Stack

| Category | Tools |
|---|---|
| **Machine Learning** | scikit-learn (Random Forest), pandas, numpy |
| **Explainability** | SHAP (TreeExplainer) |
| **LLM / GenAI** | Google Gemini API (gemini-2.5-flash) |
| **Packet Capture** | scapy, Wireshark / tshark, Npcap |
| **Frontend** | Streamlit |
| **Visualization** | matplotlib, Streamlit Charts |
| **Language** | Python 3.10+ |

---

## 📊 Model Performance

| Metric | Score |
|---|---|
| **Accuracy** | 99.75% |
| **Cross-Validation** | 99.79% (±0.11%) |
| **DoS Detection** | 100% F1 |
| **Probe Detection** | 100% F1 |
| **R2L Detection** | 99% F1 |
| **U2R Detection** | 98% F1 |

> **Note on real-world generalisation:** these scores reflect the cleanly-separated **synthetic**
> dataset. Live-capture testing (see `live_ids.py`) shows the model over-flags benign real traffic
> (false positives) — a known limitation of synthetic training data. Production use would require
> retraining on a real labelled corpus (e.g. CIC-IDS2017).

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

<div align="center">

**Built with 🔥 by [amit0hx](https://github.com/amit0hx)**

</div>
