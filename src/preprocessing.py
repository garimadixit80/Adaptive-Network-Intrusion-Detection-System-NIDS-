
# src/preprocessing.py

import pandas as pd
import numpy as np
import joblib


SELECTED_FEATURES = [
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


def load_data(file_path):
    df = pd.read_csv(file_path)
    return df


def clean_data(df):

    df.columns = df.columns.str.strip()

    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    df.dropna(inplace=True)

    df.drop_duplicates(inplace=True)

    return df


def create_features(df):

    X = df[SELECTED_FEATURES]

    return X


def create_labels(df):

    y = df["Label"].apply(
        lambda x: 0 if x == "BENIGN" else 1
    )

    return y


def scale_data(X, scaler_path="scaler.pkl"):

    scaler = joblib.load(scaler_path)

    X_scaled = scaler.transform(X)

    return X_scaled

