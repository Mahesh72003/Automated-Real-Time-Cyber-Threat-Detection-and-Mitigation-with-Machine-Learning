import pandas as pd
import joblib
from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
import numpy as np
import time

# Function to extract flow features from a single packet
def extract_packet_flow_features(pkt, flows):
    if IP in pkt:
        # Extract flow information: Source IP, Destination IP, Protocol, and Ports
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = pkt[IP].proto  # 6 = TCP, 17 = UDP

        # For TCP and UDP, we need to track source/destination ports
        if proto == 6 and TCP in pkt:  # TCP
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif proto == 17 and UDP in pkt:  # UDP
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        else:
            return  # Skip if not TCP or UDP

        # Create flow identifier (can be based on src/dst IP and ports)
        flow_key = (src_ip, dst_ip, src_port, dst_port, proto)
        if flow_key not in flows:
            flows[flow_key] = {
                "packet_count": 0,
                "byte_count": 0,
                "last_timestamp": 0,
                "fwd_header_len": 0,
                "total_backward_packets": 0,
                "flow_duration": 0
            }

        flows[flow_key]["packet_count"] += 1
        flows[flow_key]["byte_count"] += len(pkt)
        if "last_timestamp" in flows[flow_key]:
            flows[flow_key]["flow_duration"] = pkt.time - flows[flow_key]["last_timestamp"]
        flows[flow_key]["last_timestamp"] = pkt.time

        if proto == 6:  # TCP specific
            if "fwd_header_len" not in flows[flow_key]:
                flows[flow_key]["fwd_header_len"] = len(pkt[TCP].payload)
            if dst_ip == flows[flow_key]["last_timestamp"]:
                flows[flow_key]["total_backward_packets"] += 1

# Function to process PCAP and extract flows
def process_pcap(pcap_file):
    print(f"\nAnalyzing {pcap_file} for DDoS attacks...\n")
    packets = rdpcap(pcap_file)

    # Initialize flow dictionary
    flows = defaultdict(lambda: defaultdict(int))

    # Extract features from packets
    for pkt in packets:
        extract_packet_flow_features(pkt, flows)

    return flows

# Function to convert flow data into a DataFrame
def create_flow_dataframe(flows):
    flow_data = []
    for flow_key, stats in flows.items():
        flow_data.append({
            "src_ip": flow_key[0],
            "dst_ip": flow_key[1],
            "src_port": flow_key[2],
            "dst_port": flow_key[3],
            "proto": flow_key[4],
            "Flow Bytes/s": stats["byte_count"] / stats["flow_duration"] if stats["flow_duration"] > 0 else 0,
            "Flow Duration": stats["flow_duration"] if "flow_duration" in stats else 0,
            "Flow Packets/s": stats["packet_count"] / stats["flow_duration"] if stats["flow_duration"] > 0 else 0,
            "Fwd Header Length": stats["fwd_header_len"] if "fwd_header_len" in stats else 0,
            "Total Backward Packets": stats["total_backward_packets"] if "total_backward_packets" in stats else 0,
            "Total Fwd Packets": stats["packet_count"] if "packet_count" in stats else 0,  # Add this line for consistency
        })

    return pd.DataFrame(flow_data)


def detect_ddos_with_model(pcap_file, ddos_model_path="Module_Training/DDOS_Attack/ddos_model.pkl", ddos_scaler_path="Module_Training/DDOS_Attack/ddos_scaler.pkl"):
    start_time = time.time()

    # Load the trained model and scaler
    ddos_model = joblib.load(ddos_model_path)
    ddos_scaler = joblib.load(ddos_scaler_path)

    # Process PCAP file and extract features
    flows = process_pcap(pcap_file)

    # Convert flow data to DataFrame
    df_pcap = create_flow_dataframe(flows)

    # Ensure the features match exactly as during training
    features = df_pcap[["Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Flow Bytes/s", "Flow Packets/s", "Fwd Header Length"]]

    # Normalize features using the loaded scaler
    features_scaled = ddos_scaler.transform(features)

    # Predict using the loaded model
    predictions = ddos_model.predict(features_scaled)

    # Add predictions to the DataFrame
    df_pcap["Prediction"] = predictions

    # Identify DDoS packets (label = 1)
    ddos_packets = df_pcap[df_pcap["Prediction"] == 1]

    print(f"\nDetected {len(ddos_packets)} potential DDoS packets.\n")

    if len(ddos_packets) > 0:
        print("DDoS has been detected: YES")

        # Get the most common source IPs from the detected DDoS packets
        common_src_ips = ddos_packets['src_ip'].value_counts().head(1)  # Get the most frequent source IP
        print("\nSource IP with the highest count in the detected DDoS packets:")
        for ip, count in common_src_ips.items():
            print(f"Source IP: {ip} | Count: {count}")
    else:
        print("DDoS has been detected: NO")

    end_time = time.time()
    print(f"Process completed in {end_time - start_time:.2f} seconds.")

# Run detection with the loaded model and scaler on a sample PCAP file
detect_ddos_with_model("DDoS_attacktcp.pcapng")
