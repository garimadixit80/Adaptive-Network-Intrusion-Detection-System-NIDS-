import streamlit as st
import pandas as pd
import numpy as np
import joblib
import shap
import matplotlib.pyplot as plt
from pathlib import Path

# =====================================
# PAGE CONFIG
# =====================================

st.set_page_config(
    page_title="Adaptive NIDS",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Adaptive Network Intrusion Detection System")
st.caption(
    "Isolation Forest + CICIDS2017 + SHAP Explainability"
)

# =====================================
# PATHS
# =====================================

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_PATH = (
    BASE_DIR /
    "data" /
    "raw" /
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
)

MODEL_PATH = BASE_DIR / "isolation_forest.pkl"
SCALER_PATH = BASE_DIR / "scaler.pkl"

# =====================================
# LOAD MODEL
# =====================================

@st.cache_resource
def load_model():
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    return model, scaler

model, scaler = load_model()

# =====================================
# LOAD DATA
# =====================================

@st.cache_data
def load_data():

    df = pd.read_csv(
        DATA_PATH,
        nrows=5000
    )

    df.columns = df.columns.str.strip()

    df.replace(
        [np.inf, -np.inf],
        np.nan,
        inplace=True
    )

    df.dropna(inplace=True)

    return df

df = load_data()

# =====================================
# FEATURES
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

X = df[selected_features]

# =====================================
# PREDICTIONS
# =====================================

X_scaled = scaler.transform(X)

predictions = model.predict(X_scaled)

df["Prediction"] = predictions

normal_count = (predictions == 1).sum()
anomaly_count = (predictions == -1).sum()

threat_percent = round(
    anomaly_count / len(df) * 100,
    2
)

# =====================================
# KPI SECTION
# =====================================

st.subheader("📊 Detection Overview")

c1, c2, c3, c4 = st.columns(4)

c1.metric(
    "Flows Analysed",
    f"{len(df):,}"
)

c2.metric(
    "Normal Traffic",
    f"{normal_count:,}"
)

c3.metric(
    "Suspicious Traffic",
    f"{anomaly_count:,}"
)

c4.metric(
    "Threat %",
    f"{threat_percent}%"
)

st.divider()

# =====================================
# CHARTS
# =====================================

left, right = st.columns(2)

with left:

    st.subheader("Traffic Distribution")

    traffic_df = pd.DataFrame({
        "Type": ["Normal", "Suspicious"],
        "Count": [normal_count, anomaly_count]
    })

    st.bar_chart(
        traffic_df.set_index("Type")
    )

with right:

    st.subheader("Threat Ratio")

    fig, ax = plt.subplots()

    ax.pie(
        [normal_count, anomaly_count],
        labels=["Normal", "Suspicious"],
        autopct="%1.1f%%"
    )

    st.pyplot(fig)

# =====================================
# ANOMALIES
# =====================================

st.divider()

st.subheader("🚨 Top Suspicious Flows")

anomalies = df[
    df["Prediction"] == -1
]

st.dataframe(
    anomalies.head(100),
    use_container_width=True
)

st.markdown("---")
st.subheader("🔍 Explain Selected Anomaly")

if len(anomalies) > 0:

    selected_index = st.selectbox(
        "Select an anomaly row",
        anomalies.index.tolist()
    )

    selected_row = anomalies.loc[
        selected_index,
        selected_features
    ]

    st.write(
        "Selected Flow Features"
    )

    st.dataframe(
        selected_row.to_frame()
    )

# =====================================
# SHAP EXPLAINER (DEFINE ONCE)
# =====================================

explainer = shap.TreeExplainer(model)

# =====================================
# SINGLE ANOMALY EXPLANATION
# =====================================

if len(anomalies) > 0:

    st.divider()

    st.subheader("🧠 Why Was This Flow Flagged?")

    selected_scaled = scaler.transform(
        pd.DataFrame([selected_row])
    )

    single_shap = explainer.shap_values(selected_scaled)

    importance_single = pd.DataFrame({
    "Feature": selected_features,
    "SHAP Impact": np.abs(single_shap[0]).astype(float)
})

    importance_single = importance_single.sort_values(
        by="SHAP Impact",
        ascending=False
    )

    st.dataframe(importance_single, width="stretch")

    fig2, ax2 = plt.subplots(figsize=(8, 4))

    ax2.barh(
        importance_single["Feature"],
        importance_single["SHAP Impact"]
    )

    ax2.set_title("Feature Contribution")

    st.pyplot(fig2)


# =====================================
# GLOBAL SHAP SUMMARY
# =====================================

st.divider()

st.subheader("🧠 SHAP Explainability")

sample_size = min(300, len(X_scaled))
sample = X_scaled[:sample_size]

with st.spinner("Calculating SHAP values..."):

    shap_values = explainer.shap_values(sample)

fig, ax = plt.subplots(figsize=(10, 6))

shap.summary_plot(
    shap_values,
    sample,
    feature_names=selected_features,
    show=False
)

st.pyplot(plt.gcf())
plt.clf()

# =====================================
# FEATURE IMPORTANCE
# =====================================

st.subheader("📌 Feature Importance")

importance = np.abs(
    shap_values
).mean(axis=0)

importance_df = pd.DataFrame({
    "Feature": selected_features,
    "Importance": importance
})

importance_df = (
    importance_df
    .sort_values(
        by="Importance",
        ascending=False
    )
)

st.dataframe(
    importance_df,
    use_container_width=True
)

# =====================================
# MODEL DETAILS
# =====================================

st.divider()

st.subheader("⚙️ Model Information")

info = pd.DataFrame({
    "Property": [
        "Model",
        "Dataset",
        "Features",
        "Algorithm Type"
    ],
    "Value": [
        "Isolation Forest",
        "CIC-IDS2017",
        len(selected_features),
        "Unsupervised Learning"
    ]
})

st.table(info)

# =====================================
# DATASET PREVIEW
# =====================================

with st.expander(
    "📂 View Dataset Sample"
):
    st.dataframe(
        df.head(100),
        use_container_width=True
    )