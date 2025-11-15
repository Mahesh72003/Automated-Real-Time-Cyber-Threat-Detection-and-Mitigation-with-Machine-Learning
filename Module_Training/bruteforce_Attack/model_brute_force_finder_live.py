from scapy.all import sniff, IP, TCP, get_if_list
import time
import os
import json

# Define known service ports and protocols
PORTS_PROTOCOLS = {
    22: 'SSH',
    3389: 'RDP',
    445: 'SMB',
    21: 'FTP',
    80: 'HTTP',
    3306: 'MySQL',
    5432: 'PostgreSQL',
    1433: 'MSSQL',
    23: 'Telnet',
    143: 'IMAP',
    25: 'SMTP',
    110: 'POP3',
    53: 'DNS'
}

# Detection parameters
THRESHOLD = 7  # minimum attempts to alert
TIME_WINDOW = 8  # seconds sliding window

# JSON logging setup
LOG_DIR = "json log"
JSON_LOG_FILE = os.path.join(LOG_DIR, "brute_force_log.json")
os.makedirs(LOG_DIR, exist_ok=True)

# Load existing log or initialize new
if os.path.exists(JSON_LOG_FILE):
    with open(JSON_LOG_FILE, "r") as f:
        try:
            brute_force_log = json.load(f)
        except json.JSONDecodeError:
            brute_force_log = []
else:
    brute_force_log = []

# In-memory tracking of connection attempts
attempts = {}

# Track last logged attempt counts per (ip, protocol)
last_logged_attempts = {}

def log_brute_force_attempt(ip, protocol, new_attempt_count):
    """Logs or updates brute-force attempts by adding new counts cumulatively."""
    global brute_force_log
    current_time = time.strftime('%Y-%m-%d %H:%M:%S')
    updated = False

    for entry in brute_force_log:
        if entry["source_ip"] == ip and entry["protocol"] == protocol:
            entry["attempt_count"] += new_attempt_count  # Add new attempts cumulatively
            entry["timestamp"] = current_time
            updated = True
            break

    if not updated:
        # New entry if not found
        brute_force_log.append({
            "source_ip": ip,
            "protocol": protocol,
            "attempt_count": new_attempt_count,
            "timestamp": current_time
        })

    # Write updated log to JSON file
    with open(JSON_LOG_FILE, "w") as f:
        json.dump(brute_force_log, f, indent=4)

    print("📝 Brute-force attempt count updated cumulatively in JSON.")

def process_packet(packet):
    """Analyzes incoming TCP SYN packets for brute-force detection."""
    global attempts, last_logged_attempts
    current_time = time.time()

    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags

        if flags == 0x02 and dst_port in PORTS_PROTOCOLS:  # TCP SYN only
            protocol = PORTS_PROTOCOLS[dst_port]

            # Initialize tracking dicts
            if src_ip not in attempts:
                attempts[src_ip] = {}
            if protocol not in attempts[src_ip]:
                attempts[src_ip][protocol] = []

            # Remove timestamps outside the time window
            attempts[src_ip][protocol] = [
                ts for ts in attempts[src_ip][protocol]
                if current_time - ts <= TIME_WINDOW
            ]

            # Add current timestamp
            attempts[src_ip][protocol].append(current_time)
            attempt_count = len(attempts[src_ip][protocol])

            # Calculate new attempts since last alert
            key = (src_ip, protocol)
            previous_count = last_logged_attempts.get(key, 0)
            new_attempts = attempt_count - previous_count

            # Alert only if threshold crossed and we have new attempts
            if new_attempts > 0 and attempt_count > THRESHOLD:
                print(f"🚨 Brute Force Alert - Source: {src_ip}, Protocol: {protocol}, Attempts: {attempt_count}")
                log_brute_force_attempt(src_ip, protocol, new_attempts)
                last_logged_attempts[key] = attempt_count

def live_packet_capture(interface="wlan0"):
    """Begins packet sniffing on specified network interface."""
    print("Available interfaces:", get_if_list())
    print(f"📡 Starting live packet capture on interface: {interface}")
    try:
        sniff(iface=interface, prn=process_packet, store=0, filter="tcp")
    except PermissionError:
        print("❌ You need to run this script with sudo or admin privileges.")
    except Exception as e:
        print(f"❗ Error during packet capture: {e}")

if __name__ == "__main__":
    live_packet_capture(interface="wlan0")  # Change interface if needed