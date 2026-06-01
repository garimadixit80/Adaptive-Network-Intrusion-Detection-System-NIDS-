# 🛡️ Adaptive Network Intrusion Detection System (NIDS)

## Detecting Unknown Network Threats using Machine Learning, Explainable AI and Real-Time Monitoring

### Problem Statement

Traditional Intrusion Detection Systems (IDS) rely heavily on attack signatures and predefined rules. While effective against known attacks, these systems struggle to identify:

- Zero-day attacks
- Novel malware variants
- Insider threats
- Previously unseen attack patterns

As cyber threats evolve rapidly, there is a growing need for adaptive security systems capable of detecting abnormal network behavior without relying solely on known attack signatures.

---

## Proposed Solution

This project presents an Adaptive Network Intrusion Detection System (NIDS) that combines:

- Machine Learning based anomaly detection
- Explainable AI (SHAP)
- Real-time packet capture
- Live threat monitoring
- Interactive dashboards

The system learns normal network behavior from historical traffic and identifies suspicious patterns using Isolation Forests. Live packets are captured using PyShark, analyzed in real time, and visualized through a Streamlit dashboard.

---

## Objectives

- Detect anomalous network traffic
- Identify potential cyber threats
- Provide explainable predictions
- Monitor live network activity
- Visualize network behavior through dashboards

---

## 🚀 Features

### ✅ Unsupervised Anomaly Detection

* Isolation Forest based anomaly detection
* Learns normal traffic behavior
* Detects previously unseen attack patterns
* Suitable for zero-day and polymorphic threats

### ✅ SHAP Explainability

Provides feature-level explanations for anomalies, helping analysts understand why traffic was flagged.

| Feature            | Impact |
| ------------------ | ------ |
| Flow Bytes/s       | +0.52  |
| Packet Length Mean | +0.37  |
| Flow Packets/s     | +0.31  |

### ✅ Interactive Dashboard

Built using Streamlit. Includes:

- Detection Overview KPIs
- Threat Percentage
- Traffic Distribution Charts
- Suspicious Flow Explorer
- Single Anomaly SHAP Explanation
- Global SHAP Summary Plot
- Feature Importance Ranking
- Live Alert Feed
- Protocol Distribution Analysis
- Alert Distribution Analysis
- CSV Export Functionality

### ✅ Live Packet Capture

Using Wireshark, Npcap, and PyShark. Captures Source IP, Destination IP, Protocol, and Packet Size and feeds traffic into the anomaly detection pipeline.

---

## 🏗️ System Architecture

```text
                CIC-IDS2017 Dataset
                        │
                        ▼
                Data Cleaning
                        │
                        ▼
               Feature Selection
                        │
                        ▼
               Feature Scaling
                        │
                        ▼
                Isolation Forest
                        │
                        ▼
               Anomaly Detection
                        │
                        ▼
               SHAP Explainability
                        │
                        ▼
               Streamlit Dashboard
                        │
                        ▼
               Live Packet Capture
```

---

## 📡 Real-Time Detection Pipeline

```text
Internet Traffic
      ↓
PyShark Packet Capture
      ↓
Feature Extraction
      ↓
Feature Scaling
      ↓
Isolation Forest Prediction
      ↓
NORMAL / ALERT Classification
      ↓
alerts.csv Logging
      ↓
Streamlit Dashboard
```

Each captured packet logs:

- Timestamp
- Source IP
- Destination IP
- Protocol
- Packet Size
- Detection Status

Example log entry:
2026-05-31 12:18:58,18.236.121.99,192.168.31.123,TLS,816,NORMAL

---
## 📂 Project Structure

```text
nids-project/

├── data/
│   ├── raw/
│   └── processed/
│
├── notebooks/
│   ├── 01_eda.ipynb
│   └── 02_model_training.ipynb
│
├── src/
│   ├── preprocessing.py
│   ├── model.py
│   ├── evaluate.py
│   ├── live_capture.py
│   ├── live_detector.py
│   └── explainer.py
│
├── dashboard/
│   └── app.py
│
├── isolation_forest.pkl
├── scaler.pkl
├── requirements.txt
└── README.md
```

---

## 📊 Dataset

**CIC-IDS2017** — contains realistic benign and malicious traffic.

Attack Categories:

* DDoS
* Port Scan
* Web Attacks
* Infiltration
* Botnet Traffic
* Brute Force Attacks

Dataset Files:

```text
Monday-WorkingHours.pcap_ISCX.csv
Tuesday-WorkingHours.pcap_ISCX.csv
Wednesday-workingHours.pcap_ISCX.csv
Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
Friday-WorkingHours-Morning.pcap_ISCX.csv
Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
```

---

## 🔧 Data Preprocessing

### Remove Infinite Values

```python
df.replace([np.inf, -np.inf], np.nan)
```

### Remove Missing Values

```python
df.dropna()
```

### Standardize Column Names

```python
df.columns = df.columns.str.strip()
```

---

## 🎯 Feature Selection

```python
[
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Packet Length Mean',
    'Packet Length Std',
    'SYN Flag Count',
    'ACK Flag Count',
    'Average Packet Size'
]
```

These features capture traffic volume, flow behavior, packet characteristics, and TCP flag activity.

---

## 🤖 Machine Learning Model — Isolation Forest

Isolation Forest is designed specifically for anomaly detection.

Normal observations require many splits to isolate. Anomalous observations require very few splits — so **fewer splits = more suspicious**.

---

## 📈 Model Training

Training Dataset: `Monday-WorkingHours.pcap_ISCX.csv`

Reason: Mostly benign traffic, allowing the model to learn normal network behavior.

Saved Artifacts:

```text
isolation_forest.pkl
scaler.pkl
```

---

## 📊 Evaluation Results

Cross-dataset evaluation across all CIC-IDS2017 traffic files:

| Dataset           | Detection Rate |
| ----------------- | -------------- |
| DDoS              | ~62.5%         |
| Infiltration      | ~52.8%         |
| Wednesday Attacks | ~48.3%         |
| Port Scan         | Low Detection  |
| Web Attacks       | Low Detection  |

---

## 🧠 Explainable AI using SHAP

SHAP provides both local and global explanations, making the black-box model interpretable.

- **Global Explainability** — most important features across all predictions
- **Local Explainability** — why a specific flow was flagged

---

## 📊 Streamlit Dashboard

```bash
streamlit run dashboard/app.py
```

Dashboard includes Detection Overview, Threat Visualization, Suspicious Traffic Explorer, and SHAP Explainability panels.

---

## ⚙️ Installation

```bash
git clone https://github.com/garimadixit80/Adaptive-Network-Intrusion-Detection-System-NIDS-.git
cd Adaptive-Network-Intrusion-Detection-System-NIDS-
python -m venv venv
venv\Scripts\activate      # Windows
pip install -r requirements.txt
```

---

## ▶️ Usage

```bash
# Train model
python src/model.py

# Evaluate model
python src/evaluate.py

# Start live capture
python src/live_capture.py

# Run live detector
python src/live_detector.py

# Launch dashboard
streamlit run dashboard/app.py
```

---

## 🔮 Future Improvements

* Kafka-based Real-Time Streaming
* Autoencoder Deep Learning Model
* Multi-Class Attack Classification
* Threat Intelligence Integration
* Real-Time Alert System
* SIEM Integration
* Cloud Deployment

---
