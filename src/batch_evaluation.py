
import os
import pandas as pd
import numpy as np
import joblib

from sklearn.metrics import classification_report

model = joblib.load("isolation_forest.pkl")
scaler = joblib.load("scaler.pkl")

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

DATA_FOLDER = "data/raw"

print("\n===== EVALUATION SUMMARY =====\n")

for file in os.listdir(DATA_FOLDER):

    if not file.endswith(".csv"):
        continue

    path = os.path.join(DATA_FOLDER, file)

    try:

        df = pd.read_csv(path)

        df.columns = df.columns.str.strip()

        df.replace(
            [np.inf, -np.inf],
            np.nan,
            inplace=True
        )

        df.dropna(inplace=True)

        X = df[selected_features]

        X_scaled = scaler.transform(X)

        predictions = model.predict(X_scaled)

        actual = df["Label"].apply(
            lambda x: 0 if x == "BENIGN" else 1
        )

        predicted = np.where(
            predictions == -1,
            1,
            0
        )

        report = classification_report(
            actual,
            predicted,
            output_dict=True
        )

        attack_recall = report["1"]["recall"]

        print(
            f"{file:<55} "
            f"Attack Detection Rate: {attack_recall*100:.2f}%"
        )

    except Exception as e:

        print(
            f"{file:<55} ERROR"
        )
