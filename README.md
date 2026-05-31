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

## 🚀 Features

### ✅ Unsupervised Anomaly Detection

* Isolation Forest based anomaly detection
* Learns normal traffic behavior
* Detects previously unseen attack patterns
* Suitable for zero-day and polymorphic threats

### ✅ SHAP Explainability

Provides feature-level explanations for anomalies.

Example:

| Feature            | Impact |
| ------------------ | ------ |
| Flow Bytes/s       | +0.52  |
| Packet Length Mean | +0.37  |
| Flow Packets/s     | +0.31  |

This helps analysts understand why traffic was flagged.

### ✅ Interactive Dashboard

Built using Streamlit.

Dashboard includes:

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

Using:

* Wireshark
* Npcap
* PyShark

Captures:

* Source IP
* Destination IP
* Protocol
* Packet Size

and feeds traffic into the anomaly detection pipeline.

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

## 📡 Real-Time Detection Pipeline

The project includes a live traffic monitoring component.

Workflow:

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

Captured Information:

- Timestamp
- Source IP
- Destination IP
- Protocol
- Packet Size
- Detection Status

Example:

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

Dataset Used:

**CIC-IDS2017**

The dataset contains realistic benign and malicious traffic.

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

The dataset is cleaned using:

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

Selected Features:

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

These features capture:

* Traffic volume
* Flow behavior
* Packet characteristics
* TCP flag activity

---

## 🤖 Machine Learning Model

### Isolation Forest

Isolation Forest is designed specifically for anomaly detection.

#### How It Works

Normal observations:

```text
Require many splits to isolate
```

Anomalous observations:

```text
Require very few splits to isolate
```

Therefore:

```text
Fewer Splits = More Suspicious
```

---

## 📈 Model Training

Training Dataset:

```text
Monday-WorkingHours.pcap_ISCX.csv
```

Reason:

Mostly benign traffic, allowing the model to learn normal network behavior.

Saved Artifacts:

```text
isolation_forest.pkl
scaler.pkl
```

---

## 📊 Evaluation Results

Cross-dataset evaluation was performed on all CIC-IDS2017 traffic files.

Sample Results:

| Dataset           | Detection Rate |
| ----------------- | -------------- |
| DDoS              | ~62.5%         |
| Infiltration      | ~52.8%         |
| Wednesday Attacks | ~48.3%         |
| Port Scan         | Low Detection  |
| Web Attacks       | Low Detection  |

These results demonstrate the ability to identify previously unseen attack behavior.

---

## 🧠 Explainable AI using SHAP

Most anomaly detection systems act as black boxes.

SHAP provides local and global explanations.

### Global Explainability

Shows:

```text
Most Important Features Overall
```

### Local Explainability

Shows:

```text
Why a Specific Flow Was Flagged
```

Example:

```text
Flow Bytes/s          +0.52
Packet Length Mean    +0.37
Flow Packets/s        +0.31
```

---

## 📡 Live Packet Capture

Real traffic capture implemented using:

* PyShark
* Wireshark
* Npcap

Captured Information:

```text
Source IP
Destination IP
Protocol
Packet Size
```

Example:

```text
192.168.31.123 → 104.46.162.229
Protocol = TLS
Packet Size = 1336
```

---

## 📊 Streamlit Dashboard

Run:

```bash
streamlit run dashboard/app.py
```

Dashboard Features:

### Detection Overview

* Total Flows
* Normal Traffic
* Suspicious Traffic
* Threat Percentage

### Threat Visualization

* Bar Charts
* Pie Charts

### Suspicious Traffic Explorer

* Displays anomalous flows
* Interactive analysis

### SHAP Explainability

* Feature Importance
* Local Explanations

---

## ⚙️ Installation

Clone Repository:

```bash
git clone https://github.com/yourusername/nids-project.git

cd nids-project
```

Create Virtual Environment:

```bash
python -m venv venv
```

Activate Environment:

Windows:

```bash
venv\Scripts\activate
```

Install Dependencies:

```bash
pip install -r requirements.txt
```

---

## ▶️ Usage

### Train Model

```bash
python src/model.py
```

### Evaluate Model

```bash
python src/evaluate.py
```

### Start Live Capture

```bash
python src/live_capture.py
```

### Run Live Detector

```bash
python src/live_detector.py
```

### Launch Dashboard

```bash
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

## 💼 Resume Description

**Adaptive Network Intrusion Detection System (NIDS) | Python, Scikit-Learn, SHAP, Streamlit, PyShark**

* Engineered an unsupervised anomaly detection system using Isolation Forests to identify suspicious network traffic patterns.
* Implemented SHAP-based explainability to provide feature-level reasoning behind anomaly predictions.
* Developed an interactive Streamlit dashboard for threat visualization and anomaly monitoring.
* Integrated PyShark and Npcap for live packet capture and real-time traffic inspection.
* Evaluated performance across multiple CIC-IDS2017 attack scenarios including DDoS, Port Scan, Web Attacks, and Infiltration.

---

## 📜 License

This project is intended for educational, research, and portfolio purposes.

---

## 👨‍💻 Author

**Garima Dixit**

B.Tech Computer Science & Engineering

Machine Learning | Data Science | Cybersecurity