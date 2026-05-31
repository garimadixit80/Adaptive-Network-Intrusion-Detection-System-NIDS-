import asyncio
import pyshark
import pandas as pd
import joblib
import csv

from pathlib import Path
from datetime import datetime

# =====================================
# PYTHON 3.14 FIX
# =====================================

loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

# =====================================
# LOAD MODEL & SCALER
# =====================================

BASE_DIR = Path(__file__).resolve().parent.parent

print("[INFO] Loading model...")

model = joblib.load(BASE_DIR / "isolation_forest.pkl")
scaler = joblib.load(BASE_DIR / "scaler.pkl")

print("[INFO] Model loaded.")

# =====================================
# ALERT FILE
# =====================================

ALERT_FILE = (
    BASE_DIR /
    "data" /
    "processed" /
    "alerts.csv"
)

# Create file if not exists
if not ALERT_FILE.exists():
    with open(
        ALERT_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as f:
        writer = csv.writer(f)
        writer.writerow([
            "Timestamp",
            "Source_IP",
            "Destination_IP",
            "Protocol",
            "Packet_Size",
            "Status"
        ])

# =====================================
# SAVE ALERT FUNCTION
# =====================================

def save_alert(
    src_ip,
    dst_ip,
    protocol,
    packet_size,
    status
):
    with open(
        ALERT_FILE,
        "a",
        newline="",
        encoding="utf-8"
    ) as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now(),
            src_ip,
            dst_ip,
            protocol,
            packet_size,
            status
        ])

# =====================================
# NETWORK INTERFACE
# =====================================

INTERFACE = r"\Device\NPF_{B63D7F2A-1E69-4D81-B8A9-10CFD597A177}"

print(f"\n[INFO] Listening on: {INTERFACE}")
print("[INFO] Open YouTube, Google, GitHub, etc.\n")

# =====================================
# START CAPTURE
# =====================================

capture = pyshark.LiveCapture(
    interface=INTERFACE
)

packet_count = 0
normal_count = 0
anomaly_count = 0

try:
    for packet in capture.sniff_continuously(
        packet_count=100
    ):
        try:
            if not hasattr(packet, "ip"):
                continue

            packet_count += 1

            packet_size = int(
                getattr(packet, "length", 0)
            )

            protocol = getattr(
                packet,
                "highest_layer",
                "UNKNOWN"
            )

            src_ip = packet.ip.src
            dst_ip = packet.ip.dst

            row = pd.DataFrame([{
                "Flow Duration": 1,
                "Total Fwd Packets": 1,
                "Total Backward Packets": 0,
                "Flow Bytes/s": packet_size,
                "Flow Packets/s": 1,
                "Packet Length Mean": packet_size,
                "Packet Length Std": 0,
                "SYN Flag Count": 0,
                "ACK Flag Count": 0,
                "Average Packet Size": packet_size
            }])

            row_scaled = scaler.transform(row)

            prediction = model.predict(
                row_scaled
            )[0]

            # ==========================
            # ANOMALY
            # ==========================

            if prediction == -1:

                anomaly_count += 1

                save_alert(
                    src_ip,
                    dst_ip,
                    protocol,
                    packet_size,
                    "ALERT"
                )

                print(
                    f"[ALERT] "
                    f"{src_ip} -> {dst_ip} | "
                    f"{protocol} | "
                    f"Size={packet_size}"
                )

            # ==========================
            # NORMAL
            # ==========================

            else:

                normal_count += 1

                save_alert(
                    src_ip,
                    dst_ip,
                    protocol,
                    packet_size,
                    "NORMAL"
                )

                print(
                    f"[NORMAL] "
                    f"{src_ip} -> {dst_ip} | "
                    f"{protocol} | "
                    f"Size={packet_size}"
                )

            # ==========================
            # SUMMARY
            # ==========================

            if packet_count % 50 == 0:

                print("\n========== SUMMARY ==========")
                print(f"Packets   : {packet_count}")
                print(f"Normal    : {normal_count}")
                print(f"Anomalies : {anomaly_count}")
                print("=============================\n")

        except Exception as packet_error:
            print(
                f"[ERROR] Packet Processing: {packet_error}"
            )

except KeyboardInterrupt:
    print("\nCapture stopped.")

except Exception as capture_error:
    print(
        f"\n[ERROR] Capture Error: {capture_error}"
    )

finally:
    try:
        capture.close()
    except Exception:
        pass

print("\n========== FINAL SUMMARY ==========")
print(f"Packets   : {packet_count}")
print(f"Normal    : {normal_count}")
print(f"Anomalies : {anomaly_count}")
print("===================================")