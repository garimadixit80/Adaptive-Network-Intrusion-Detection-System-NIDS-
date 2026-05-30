
import pandas as pd
import numpy as np
import joblib

from sklearn.metrics import (
    confusion_matrix,
    classification_report
)

# =====================================
# Load Model and Scaler
# =====================================

print("[INFO] Loading model...")

model = joblib.load("isolation_forest.pkl")
scaler = joblib.load("scaler.pkl")

print("[INFO] Model loaded.")

# =====================================
# Load Attack Dataset
# =====================================

DATA_PATH = (
    "data/raw/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
)

print(f"[INFO] Loading dataset: {DATA_PATH}")

df = pd.read_csv(DATA_PATH)

print("[INFO] Dataset loaded.")

# =====================================
# Clean Data
# =====================================

df.columns = df.columns.str.strip()

df.replace(
    [np.inf, -np.inf],
    np.nan,
    inplace=True
)

df.dropna(inplace=True)

df.drop_duplicates(inplace=True)

print("[INFO] Data cleaned.")

# =====================================
# Show Actual Labels
# =====================================

print("\n========== ACTUAL LABEL DISTRIBUTION ==========")

print(df["Label"].value_counts())

# =====================================
# Features Used During Training
# =====================================

selected_features = [
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

# =====================================
# Create Feature Matrix
# =====================================

X = df[selected_features]

# =====================================
# Scale Features
# =====================================

X_scaled = scaler.transform(X)

# =====================================
# Predict
# =====================================

print("[INFO] Running predictions...")

predictions = model.predict(X_scaled)

print("[INFO] Predictions completed.")

# =====================================
# Count Results
# =====================================

normal_count = (predictions == 1).sum()

anomaly_count = (predictions == -1).sum()

detection_rate = round(
    (anomaly_count / len(df)) * 100,
    2
)

print("\n========== RESULTS ==========")

print("Total Samples :", len(df))
print("Normal        :", normal_count)
print("Anomalies     :", anomaly_count)
print("Detection Rate:", detection_rate, "%")

# =====================================
# Convert Labels
# =====================================

actual = df["Label"].apply(
    lambda x: 0 if x == "BENIGN" else 1
)

predicted = np.where(
    predictions == -1,
    1,
    0
)

# =====================================
# Confusion Matrix
# =====================================

print("\n========== CONFUSION MATRIX ==========")

cm = confusion_matrix(
    actual,
    predicted
)

print(cm)

# =====================================
# Classification Report
# =====================================

print("\n========== CLASSIFICATION REPORT ==========")

print(
    classification_report(
        actual,
        predicted
    )
)

# =====================================
# Attack Detection Breakdown
# =====================================

attack_rows = actual.sum()

detected_attacks = (
    (actual == 1) &
    (predicted == 1)
).sum()

if attack_rows > 0:

    attack_detection_rate = round(
        detected_attacks /
        attack_rows * 100,
        2
    )

    print(
        "\nAttack Detection Rate:",
        attack_detection_rate,
        "%"
    )

print("\n[INFO] Evaluation Complete.")
