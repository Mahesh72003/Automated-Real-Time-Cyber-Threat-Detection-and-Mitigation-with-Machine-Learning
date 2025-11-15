from scapy.all import rdpcap, IP, TCP
import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler
import pyshark

# Define known ports and protocols
PORTS_PROTOCOLS = {
    22: 'SSH',
    3389: 'RDP',
    445: 'SMB',
    21: 'FTP',
    80: 'HTTP',
    443: 'HTTPS',
    3306: 'MySQL',
    5432: 'PostgreSQL',
    1433: 'MSSQL',
    23: 'Telnet',
    143: 'IMAP',
    25: 'SMTP',
    110: 'POP3',
    53: 'DNS'
}

# Load trained ML model
model = joblib.load('brute_force_detector_rf.pkl')

async def extract_features_from_pcap(pcap_file):
    cap = pyshark.FileCapture(pcap_file, use_json=True, disable_protocol='ssl')  # Disable SSL to speed up parsing
    features = []

    try:
        async for packet in cap:  # Use async iteration
            if 'IP' in packet:
                try:
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    protocol = packet.transport_layer  # TCP/UDP
                    packet_len = len(packet)

                    features.append([packet_len, src_ip, dst_ip, protocol])
                except AttributeError:
                    continue  # Skip packets without IP layer
    finally:
        await cap.close()  # Properly close capture

    df = pd.DataFrame(features, columns=['packet_len', 'src_ip', 'dst_ip', 'protocol'])
    return df

def preprocess_for_prediction(df):
    """Preprocess the data for model prediction."""
    df['src_ip'] = df['src_ip'].apply(lambda x: hash(x) % 1_000_000)
    df['dst_ip'] = df['dst_ip'].apply(lambda x: hash(x) % 1_000_000)
    df['protocol'] = pd.Categorical(df['protocol']).codes

    scaler = StandardScaler()
    df['packet_len'] = scaler.fit_transform(df[['packet_len']])

    return df

def predict_brute_force_attack(df):
    """Use the trained model to predict brute force attacks."""
    X = df[['packet_len', 'src_ip', 'dst_ip', 'protocol']]
    predictions = model.predict(X)
    return predictions

async def extract_features_from_pcap(pcap_file):
    cap = pyshark.FileCapture(pcap_file, use_json=True, disable_protocol='ssl')  # Disable SSL to speed up parsing
    features = []

    try:
        async for packet in cap:  # Use async iteration
            if 'IP' in packet:
                try:
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    protocol = packet.transport_layer  # TCP/UDP
                    packet_len = len(packet)

                    features.append([packet_len, src_ip, dst_ip, protocol])
                except AttributeError:
                    continue  # Skip packets without IP layer
    finally:
        await cap.close()  # Properly close capture

    df = pd.DataFrame(features, columns=['packet_len', 'src_ip', 'dst_ip', 'protocol'])
    return df

def preprocess_for_prediction(df):
    """Preprocess the data for model prediction."""
    df['src_ip'] = df['src_ip'].apply(lambda x: hash(x) % 1_000_000)
    df['dst_ip'] = df['dst_ip'].apply(lambda x: hash(x) % 1_000_000)
    df['protocol'] = pd.Categorical(df['protocol']).codes

    scaler = StandardScaler()
    df['packet_len'] = scaler.fit_transform(df[['packet_len']])

    return df

# Load the pcap file
pcap_file = "Brute_Force_attackmysql.pcapng"
packets = rdpcap(pcap_file)

# Dictionary to count connection attempts per source IP
attempts = {}

# Process packets
for packet in packets:
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        
        if dst_port in PORTS_PROTOCOLS:
            protocol = PORTS_PROTOCOLS[dst_port]
            
            if src_ip in attempts:
                attempts[src_ip][protocol] = attempts[src_ip].get(protocol, 0) + 1
            else:
                attempts[src_ip] = {protocol: 1}

# Find the maximum number of attempts
max_attempts = max(max(protocols.values()) for protocols in attempts.values())

# Check for and print only the connections with the maximum attempts
brute_force_detected = False
for ip, protocols in attempts.items():
    for protocol, count in protocols.items():
        if count == max_attempts:  # Only print connections with the highest attempts
            print(f"YES - Source: {ip}, Protocol: {protocol}, Attempts: {count}")
            brute_force_detected = True

if not brute_force_detected:
    print("NO - There is no brute force attack with the highest number of attempts.")
