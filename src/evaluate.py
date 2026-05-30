import pandas as pd
import numpy as np
import joblib
from sklearn.metrics import classification_report, confusion_matrix

# Load model
model = joblib.load("isolation_forest.pkl")
scaler = joblib.load("scaler.pkl")

# Load data
df = pd.read_csv("data/raw/Monday-WorkingHours.pcap_ISCX.csv")

df.columns = df.columns.str.strip()
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

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

X_scaled = scaler.transform(X)

preds = model.predict(X_scaled)

# Convert Isolation Forest output
preds = np.where(preds == -1, 1, 0)

print(confusion_matrix(y, preds))
print(classification_report(y, preds))