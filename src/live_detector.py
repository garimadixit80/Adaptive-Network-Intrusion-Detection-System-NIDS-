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

ALERT_FILE = BASE_DIR / "data" / "processed" / "alerts.csv"

ALERT_FILE.parent.mkdir(parents=True, exist_ok=True)

# =====================================
# CREATE CSV IF NOT EXISTS
# =====================================

if not ALERT_FILE.exists():
    with open(ALERT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Timestamp",
            "Source_IP",
            "Destination_IP",
            "Protocol",
            "Packet_Size",
            "Status",
            "Severity"
        ])

# =====================================
# SAVE ALERT
# =====================================

def save_alert(src_ip, dst_ip, protocol, packet_size, status, severity):
    with open(ALERT_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now(),
            src_ip,
            dst_ip,
            protocol,
            packet_size,
            status,
            severity
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

capture = pyshark.LiveCapture(interface=INTERFACE)

packet_count = 0
normal_count = 0
anomaly_count = 0

high_count = 0
medium_count = 0
low_count = 0

try:
    for packet in capture.sniff_continuously():

        try:
            if not hasattr(packet, "ip"):
                continue

            packet_count += 1

            packet_size = int(getattr(packet, "length", 0))
            protocol = getattr(packet, "highest_layer", "UNKNOWN")
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst

            # =====================================
            # FEATURE VECTOR
            # =====================================

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
            prediction = model.predict(row_scaled)[0]

            # =====================================
            # SEVERITY
            # =====================================

            if packet_size > 1200:
                severity = "HIGH"
                high_count += 1
            elif packet_size > 600:
                severity = "MEDIUM"
                medium_count += 1
            else:
                severity = "LOW"
                low_count += 1

            # =====================================
            # ALERT
            # =====================================

            if prediction == -1:
                anomaly_count += 1
                save_alert(src_ip, dst_ip, protocol, packet_size, "ALERT", severity)
                print(
                    f"[ALERT-{severity}] "
                    f"{src_ip} -> {dst_ip} | "
                    f"{protocol} | "
                    f"Size={packet_size}"
                )

            # =====================================
            # NORMAL
            # =====================================

            else:
                normal_count += 1
                save_alert(src_ip, dst_ip, protocol, packet_size, "NORMAL", severity)
                print(
                    f"[NORMAL-{severity}] "
                    f"{src_ip} -> {dst_ip} | "
                    f"{protocol} | "
                    f"Size={packet_size}"
                )

            # =====================================
            # SUMMARY (every 50 packets)
            # =====================================

            if packet_count % 50 == 0:
                print("\n========== SUMMARY ==========")
                print(f"Packets   : {packet_count}")
                print(f"Normal    : {normal_count}")
                print(f"Anomalies : {anomaly_count}")
                print(f"HIGH      : {high_count}")
                print(f"MEDIUM    : {medium_count}")
                print(f"LOW       : {low_count}")
                print("=============================\n")

        except Exception as packet_error:
            print(f"[ERROR] Packet Processing: {packet_error}")

except KeyboardInterrupt:
    print("\n[INFO] Capture stopped by user.")

except Exception as capture_error:
    print(f"\n[ERROR] Capture Error: {capture_error}")

finally:
    try:
        capture.close()
    except Exception:
        pass

print("\n========== FINAL SUMMARY ==========")
print(f"Packets   : {packet_count}")
print(f"Normal    : {normal_count}")
print(f"Anomalies : {anomaly_count}")
print(f"HIGH      : {high_count}")
print(f"MEDIUM    : {medium_count}")
print(f"LOW       : {low_count}")
print("===================================")