
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
import joblib
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from preprocessing import *


# -----------------------------
# LOAD DATA
# -----------------------------

df = pd.read_csv("data/raw/Monday-WorkingHours.pcap_ISCX.csv")

# -----------------------------
# CLEAN DATA
# -----------------------------

df.columns = df.columns.str.strip()

df.replace([np.inf, -np.inf], np.nan, inplace=True)

df.dropna(inplace=True)

df.drop_duplicates(inplace=True)

# -----------------------------
# FEATURE SELECTION
# -----------------------------

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

X = df[selected_features]

y = df['Label'].apply(
    lambda x: 0 if x == 'BENIGN' else 1
)

# -----------------------------
# SCALE FEATURES
# -----------------------------

scaler = StandardScaler()

X_scaled = scaler.fit_transform(X)

# Save scaler
joblib.dump(scaler, "scaler.pkl")

# -----------------------------
# TRAIN ONLY ON BENIGN
# -----------------------------

X_benign = X_scaled[y == 0]

X_train, X_test = train_test_split(
    X_benign,
    test_size=0.2,
    random_state=42
)

# -----------------------------
# TRAIN MODEL
# -----------------------------

model = IsolationForest(
    n_estimators=100,
    contamination=0.02,
    random_state=42
)

print("[INFO] Training model...")

model.fit(X_train)

print("[INFO] Model trained.")

# Save model
joblib.dump(model, "isolation_forest.pkl")

print("[INFO] Model saved.")
