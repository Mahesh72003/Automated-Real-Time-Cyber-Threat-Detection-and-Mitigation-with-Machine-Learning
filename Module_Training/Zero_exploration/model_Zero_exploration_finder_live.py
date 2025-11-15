import pyshark
import pandas as pd
import numpy as np
import joblib
import json
import time
import ipaddress
from sklearn.neighbors import NearestNeighbors
from sklearn.cluster import KMeans
from collections import defaultdict

# === CONFIG ===
INTERFACE = "wlan0"
DEBUG = True  # Set to False to disable console logs

SCALER_PATH = "/home/mahesh/mahesh2003/project/Module_Training/Zero_exploration/ZeroDay_Scaler.joblib"
RF_MODEL_PATH = "/home/mahesh/mahesh2003/project/Module_Training/Zero_exploration/ZeroDay_RandomForest.joblib"
XGB_MODEL_PATH = "/home/mahesh/mahesh2003/project/Module_Training/Zero_exploration/ZeroDay_XGBoost.joblib"
LOG_FILE = "/home/mahesh/mahesh2003/project/json log/ZeroDay_suspicious_flows_log.json"
SUSPICIOUS_IPS_FILE = "/home/mahesh/mahesh2003/project/json log/ZeroDay_suspicious_ips.json"

# WHITELISTED IP NETWORKS
WHITELIST_IPS = [
    # Microsoft
    "13.107.6.171/32", "13.107.18.15/32", "13.107.140.6/32", "52.108.0.0/14", "52.244.37.168/32",
    "20.20.32.0/19", "20.190.128.0/18", "20.231.128.0/19", "40.126.0.0/18",
    "13.107.6.192/32", "13.107.9.192/32", "13.107.42.0/24", "20.0.0.0/8", "20.48.0.0/12",
    "18.155.96.0/21", "104.208.0.0/13", "13.104.0.0/14",
    # Google
    "142.250.0.0/15", "172.217.0.0/16", "8.8.8.8/32", "8.8.4.4/32", "216.239.32.0/19",
    "64.233.160.0/19", "66.102.0.0/20", "66.249.80.0/20", "72.14.192.0/18", "74.125.0.0/16",
    "209.85.128.0/17", "173.194.0.0/16", "108.177.8.0/21", "216.58.192.0/19",
    # Telegram
    "149.154.160.0/20", "91.108.0.0/16",
    # Cloudflare
    "104.16.0.0/12", "13.202.0.0/15",
    # Local / SSDP
    "239.255.255.250","10.42.0.1","10.42.0.133",
    # Indian Networks
    "164.100.0.0/16", "117.192.0.0/10", "49.32.0.0/11", "223.176.0.0/12", "14.140.0.0/14",
    "203.200.64.0/19", "202.54.112.0/20", "203.90.242.0/23", "14.139.0.0/16", "103.195.64.0/22"
]

WHITELIST_NETWORKS = [ipaddress.ip_network(ip) for ip in WHITELIST_IPS]
suspicious_ip_counts = defaultdict(lambda: {"count": 0, "protocols": set()})

def is_ip_whitelisted(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return any(ip_obj in net for net in WHITELIST_NETWORKS)
    except Exception:
        return False

def save_suspicious_ip_counts():
    current_time = time.strftime('%Y-%m-%d %H:%M:%S')
    output = {
        ip: {"count": data["count"], "protocols": list(data["protocols"]), "timestamp": current_time}
        for ip, data in suspicious_ip_counts.items()
    }
    with open(SUSPICIOUS_IPS_FILE, "w") as f:
        json.dump(output, f, indent=2)

def log_suspicious_flows(suspicious_df):
    logs = []
    current_time = time.strftime('%Y-%m-%d %H:%M:%S')
    for _, row in suspicious_df.iterrows():
        for ip_type, ip in [("Source", row["Source IP"]), ("Destination", row["Destination IP"])]:
            if not is_ip_whitelisted(ip):
                suspicious_ip_counts[ip]["count"] += 1
                suspicious_ip_counts[ip]["protocols"].add(row["Protocol"])
                logs.append({
                    "IP": ip,
                    "Type": ip_type,
                    "Count": suspicious_ip_counts[ip]["count"],
                    "Protocol": row["Protocol"],
                    "timestamp": current_time
                })
                if DEBUG:
                    print(f"❌ Suspicious {ip_type} IP: {ip}")

    if logs:
        with open(LOG_FILE, "a") as f:
            for entry in logs:
                f.write(json.dumps(entry) + "\n")

        save_suspicious_ip_counts()

        for ip, data in suspicious_ip_counts.items():
            if data["count"] > 5:
                print(f"⚠️ High Suspicion: {ip} detected {data['count']} times")

# === Load Models ===
scaler = joblib.load(SCALER_PATH)
rf_model = joblib.load(RF_MODEL_PATH)
xgb_model = joblib.load(XGB_MODEL_PATH)
scaler_features = list(scaler.feature_names_in_)

print("✅ Live Zero-Day Detection Running on:", INTERFACE)
cap = pyshark.LiveCapture(interface=INTERFACE)
flows = {}

def get_flow_key(pkt):
    try:
        if hasattr(pkt, 'ip') and hasattr(pkt, pkt.transport_layer):
            return f"{pkt.ip.src}-{pkt.ip.dst}-{pkt[pkt.transport_layer].srcport}-{pkt[pkt.transport_layer].dstport}-{pkt.transport_layer}"
    except Exception:
        return None

def process_flow_data():
    if not flows:
        return

    rows = []
    for flow in flows.values():
        duration = (flow["end_time"] - flow["start_time"]) * 1e6
        fwd_iats = flow["fwd_iats"]
        bwd_iats = flow["bwd_iats"]
        row = {
            "Flow Duration": duration,
            "Total Fwd Packets": flow["total_fwd_packets"],
            "Fwd Packet Length Mean": np.mean(flow["fwd_lengths"]) if flow["fwd_lengths"] else 0,
            "Bwd Packet Length Mean": np.mean(flow["bwd_lengths"]) if flow["bwd_lengths"] else 0,
            "Fwd IAT Mean": np.mean(fwd_iats) if fwd_iats else 0,
            "Bwd IAT Mean": np.mean(bwd_iats) if bwd_iats else 0,
            "Destination Port": flow["dst_port"],
            "Flow IAT Mean": np.mean(fwd_iats + bwd_iats) if fwd_iats or bwd_iats else 0,
            "Fwd Packet Length Max": max(flow["fwd_lengths"], default=0),
            "Bwd Packet Length Max": max(flow["bwd_lengths"], default=0),
            "Fwd Packet Length Min": min(flow["fwd_lengths"], default=0),
            "Source IP": flow["src_ip"],
            "Destination IP": flow["dst_ip"],
            "Protocol": flow["protocol"]
        }
        rows.append(row)

    df = pd.DataFrame(rows)
    if df.empty:
        return

    try:
        X_base = df[scaler_features]
        X_scaled = scaler.transform(X_base)

        if len(X_base) >= 2:
            knn = NearestNeighbors(n_neighbors=2)
            knn.fit(X_base)
            distances, _ = knn.kneighbors(X_base)
            knn_scores = distances[:, 1]
            kmeans_labels = KMeans(n_clusters=2, n_init=10).fit_predict(X_base)
        else:
            knn_scores = np.zeros(len(X_base))
            kmeans_labels = np.zeros(len(X_base))

        X_final = pd.DataFrame(X_scaled, columns=scaler_features)
        X_final["knn_score"] = knn_scores
        X_final["kmeans_cluster"] = kmeans_labels

        df["Prediction_RF"] = rf_model.predict(X_final)
        df["Prediction_XGB"] = xgb_model.predict(X_final)
        df["Final_Prediction"] = (df["Prediction_RF"] + df["Prediction_XGB"]) > 0

        suspicious = df[df["Final_Prediction"] == True]
        if not suspicious.empty:
            print("\n🚨 Detected Suspicious Flows:")
            print(suspicious[["Source IP", "Destination IP", "Protocol"]])
            log_suspicious_flows(suspicious)

    except Exception as e:
        print("⚠️ Error during processing:", e)

    flows.clear()

# === Packet Processing Loop ===
start_time = time.time()
for pkt in cap.sniff_continuously():
    try:
        key = get_flow_key(pkt)
        if not key:
            continue

        timestamp = float(pkt.sniff_timestamp)
        length = int(pkt.length)
        direction = "fwd" if pkt.ip.src < pkt.ip.dst else "bwd"

        if key not in flows:
            flows[key] = {
                "start_time": timestamp, "end_time": timestamp,
                "total_fwd_packets": 0,
                "fwd_lengths": [], "bwd_lengths": [],
                "fwd_iats": [], "bwd_iats": [],
                "last_fwd_time": None, "last_bwd_time": None,
                "dst_port": int(pkt[pkt.transport_layer].dstport),
                "src_ip": pkt.ip.src, "dst_ip": pkt.ip.dst,
                "protocol": pkt.transport_layer
            }

        flow = flows[key]
        flow["end_time"] = timestamp

        if direction == "fwd":
            flow["total_fwd_packets"] += 1
            flow["fwd_lengths"].append(length)
            if flow["last_fwd_time"] is not None:
                flow["fwd_iats"].append(timestamp - flow["last_fwd_time"])
            flow["last_fwd_time"] = timestamp
        else:
            flow["bwd_lengths"].append(length)
            if flow["last_bwd_time"] is not None:
                flow["bwd_iats"].append(timestamp - flow["last_bwd_time"])
            flow["last_bwd_time"] = timestamp

        if time.time() - start_time >= 10:
            process_flow_data()
            start_time = time.time()

    except Exception:
        continue
