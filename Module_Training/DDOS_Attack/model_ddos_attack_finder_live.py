import subprocess
import time
import pandas as pd
import joblib
import os
import json

# Load trained ML model & scaler
ddos_model = joblib.load("Module_Training/DDOS_Attack/ddos_model.pkl")
ddos_scaler = joblib.load("Module_Training/DDOS_Attack/ddos_scaler.pkl")

LOG_DIR = "/home/mahesh/mahesh2003/project/json log"
LOG_FILE = os.path.join(LOG_DIR, "ddos_log_live.csv")
DDOS_JSON_FILE = os.path.join(LOG_DIR, "ddos_log_live.json")
os.makedirs(LOG_DIR, exist_ok=True)
BATCH_SIZE = 30  
IP_THRESHOLD = 50  # If an IP sends more than 100 packets in 1 minute
SHORT_BURST_THRESHOLD = 50  # If an IP sends 50 packets in 7 seconds
TIME_WINDOW = 60  # 1 minute
SHORT_TIME_WINDOW = 5  # 7 seconds

def capture_packets(duration=10, interface="wlan0"):
    """ Captures network packets using Tshark and logs IPs """
    print(f"Capturing network traffic on {interface} for {duration} seconds...")

    cmd = ["tshark", "-i", interface, "-T", "fields", "-e", "ip.src", "-c", "50"]  # Capture 50 packets

    try:
        process = subprocess.run(cmd, capture_output=True, text=True)
        packets = process.stdout.strip().split("\n")

        # Remove empty values
        packets = [ip for ip in packets if ip]

        print("Captured IPs:", packets)

        if not packets:
            print("❌ No packets captured! Check Tshark installation.")
            return []

        log_ips(packets)
        return packets

    except Exception as e:
        print(f"❌ Error capturing packets: {e}")
        return []

def log_ips(ip_list):
    """ Logs captured IPs with dummy network flow features """
    timestamp = time.time()

    df = pd.DataFrame({
        "IP": ip_list,
        "Timestamp": [timestamp] * len(ip_list),
        "Flow Duration": [10] * len(ip_list),
        "Total Fwd Packets": [5] * len(ip_list),
        "Total Backward Packets": [2] * len(ip_list),
        "Flow Bytes/s": [500] * len(ip_list),
        "Flow Packets/s": [50] * len(ip_list),
        "Fwd Header Length": [40] * len(ip_list)
    })

    df.to_csv(LOG_FILE, mode='a', header=not os.path.exists(LOG_FILE), index=False)
    
    print(f"✅ Logged {len(ip_list)} IPs with additional flow features.")

def log_ddos_json(ddos_ips_1min, ddos_ips_short):
    """Logs detected DDoS attacks in a JSON file, keeping only the first occurrence per source_ip."""
    data = []
    if os.path.exists(DDOS_JSON_FILE):
        with open(DDOS_JSON_FILE, "r") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = []

    current_time = time.strftime('%Y-%m-%d %H:%M:%S')
    existing_ips = {entry["source_ip"] for entry in data}

    detected_ips = set(ddos_ips_1min.index).union(ddos_ips_short.index)
    print(f"💡 Debug: Final detected IPs -> {detected_ips}")

    for ip in detected_ips:
        if ip not in existing_ips:
            entry = {
                "source_ip": ip,
                "total_packets_1min": int(ddos_ips_1min.get(ip, 0)),
                "total_packets_7sec": int(ddos_ips_short.get(ip, 0)),
                "is_ddos": True,
                "timestamp": current_time
            }
            data.append(entry)

    with open(DDOS_JSON_FILE, "w") as f:
        json.dump(data, f, indent=4)

    print("📄 JSON log updated with DDoS detections.")


def detect_ddos():
    """ Detects DDoS based on total packets in 1 minute and bursts within 7 seconds """
    if not os.path.exists(LOG_FILE):
        print("⚠️ No log file found. Skipping DDoS detection.")
        return

    try:
        df = pd.read_csv(LOG_FILE)

        expected_columns = [
            "IP", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
            "Flow Bytes/s", "Flow Packets/s", "Fwd Header Length", "Timestamp"
        ]
        
        if not all(col in df.columns for col in expected_columns):
            raise ValueError(f"❌ CSV Columns mismatch! Expected: {expected_columns}, Found: {df.columns.tolist()}")

        df.dropna(inplace=True)

        df["Timestamp"] = pd.to_numeric(df["Timestamp"], errors='coerce')
        df.dropna(subset=["Timestamp"], inplace=True)

        current_time = time.time()

        df_1min = df[df["Timestamp"] >= current_time - TIME_WINDOW]
        ip_counts_1min = df_1min["IP"].value_counts()
        ddos_candidates_1min = ip_counts_1min[ip_counts_1min > IP_THRESHOLD]

        df_short = df[df["Timestamp"] >= current_time - SHORT_TIME_WINDOW]
        ip_counts_short = df_short["IP"].value_counts()
        ddos_candidates_short = ip_counts_short[ip_counts_short > SHORT_BURST_THRESHOLD]

        if not ddos_candidates_1min.empty:
            print(f"🚨 DDoS Alert! IPs exceeding 100 packets in 1 minute: {ddos_candidates_1min}")

        if not ddos_candidates_short.empty:
            print(f"⚠️ DDoS Burst Alert! IPs sending 50+ packets in 7 sec: {ddos_candidates_short}")

        log_ddos_json(ddos_candidates_1min, ddos_candidates_short)

    except Exception as e:
        print(f"❌ Error detecting DDoS: {e}")

try:
    while True:
        capture_packets()
        detect_ddos()
        print("🔁 Waiting 10 seconds before next scan...\n")
        time.sleep(10)
except KeyboardInterrupt:
    print("\n🛑 Stopping packet capture and DDoS detection.")
