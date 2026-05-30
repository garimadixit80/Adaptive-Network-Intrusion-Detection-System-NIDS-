
import pandas as pd
import numpy as np
import joblib
import shap

# Load model
model = joblib.load("isolation_forest.pkl")
scaler = joblib.load("scaler.pkl")

# Load DDoS dataset
df = pd.read_csv(
    "data/raw/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
)

df.columns = df.columns.str.strip()

df.replace(
    [np.inf, -np.inf],
    np.nan,
    inplace=True
)

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

X_scaled = scaler.transform(X)

# Take small sample
sample = X_scaled[:500]

print("Creating SHAP explainer...")

explainer = shap.TreeExplainer(model)

print("Calculating SHAP values...")

shap_values = explainer.shap_values(sample)

print("Generating summary plot...")

shap.summary_plot(
    shap_values,
    sample,
    feature_names=selected_features
)
