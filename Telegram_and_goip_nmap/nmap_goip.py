import json
import time
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
import subprocess
import re
import requests
import shutil
import asyncio
from telegram import Bot

# === Telegram Bot Setup ===
BOT_TOKEN = '7503247145:AAGKkFDTmRamUTreDS_IN2Joofq1EUv2Kqg'
CHAT_ID = '1542494811'
bot = Bot(token=BOT_TOKEN)

# Define the mapping of file names to full paths
file_paths = {
    "brute_force_log.json": "/home/mahesh/mahesh2003/project/json log/brute_force_log.json",
    "ddos_log_live.json": "/home/mahesh/mahesh2003/project/json log/ddos_log_live.json",
    "sql_injection_log.json": "/home/mahesh/mahesh2003/project/json log/sql_injection_log.json",
    "ZeroDay_suspicious_ips.json": "/home/mahesh/mahesh2003/project/json log/ZeroDay_suspicious_ips.json"
}
JSON_PATH = "/home/mahesh/mahesh2003/project/json log/finial_result.json"
# === Attack Type Mapping ===
attack_type_mapping = {
    'brute_force_log.json': 'Brute Force Attack',
    'ddos_log_live.json': 'DDOS Attack',
    'sql_injection_log.json': 'SQL Injection Attack',
    'ZeroDay_suspicious_ips.json': 'Zero-Day Exploit Attack'
}

# Helper to parse timestamps
def parse_timestamp(ts):
    return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")

# Function to handle the updated file
def process_file(file_path, file_name, last_processed):
    try:
        with open(file_path, "r") as f:
            contents = f.read().strip()
            if not contents:
                print(f"[Warning] {file_name} is empty or not ready. Skipping...")
                return
            data = json.loads(contents)

            condition_met = False
            ip_address_nmap = None

            if file_name == "ZeroDay_suspicious_ips.json":
                latest_ip = max(data.items(), key=lambda item: parse_timestamp(item[1]["timestamp"]))
                ip_address_nmap = latest_ip[0]
                condition_met = latest_ip[1].get("count", 0) > 7

            elif file_name == "brute_force_log.json":
                latest_entry = max(data, key=lambda x: parse_timestamp(x["timestamp"]))
                ip_address_nmap = latest_entry["source_ip"]
                condition_met = latest_entry.get("attempt_count", 0) > 7

            elif file_name == "ddos_log_live.json":
                latest_entry = max(data, key=lambda x: parse_timestamp(x["timestamp"]))
                ip_address_nmap = latest_entry["source_ip"]
                condition_met = latest_entry.get("total_packets_1min", 0) > 100

            elif file_name == "sql_injection_log.json":
                latest_entry = max(data, key=lambda x: parse_timestamp(x["timestamp"]))
                ip_address_nmap = latest_entry["source_ip"]
                condition_met = True  # Add specific logic here if needed

            if not condition_met:
                print(f"[Info] Condition not met for {file_name}. Skipping...")
                return
            else:
                if last_processed.get(file_name) == ip_address_nmap:
                    return

                last_processed[file_name] = ip_address_nmap
                print(f"The IP address or attack is {ip_address_nmap}, the file name is {file_name}")
                nmap_finder_goip(ip_address_nmap, file_name, last_processed)
                ip_blocker(ip_address_nmap)
                send_alert_from_file()

    except Exception as e:
        print(f"[Error] Failed to process {file_name}: {e}")

# Watchdog event handler
class LogFileHandler(FileSystemEventHandler):
    def on_modified(self, event):
        time.sleep(1)  # Increased delay to ensure file write is complete
        if not event.is_directory:
            if "nmap_results.json" in event.src_path:
                return

            for file_name, path in file_paths.items():
                if os.path.abspath(event.src_path) == os.path.abspath(path):
                    process_file(path, file_name, last_processed)

# Location API for public IP location details
def get_ip_location(ip):
    url = f"http://ip-api.com/json/{ip}"
    response = requests.get(url)
    data = response.json()

    if data["status"] == "success":
        return {
            "ip": ip,
            "country": data.get("country"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "isp": data.get("isp"),
            "org": data.get("org")
        }
    else:
        return {"ip": ip, "error": data.get("message", "Unknown error")}

# Perform Nmap scan and get device and location information
def nmap_finder_goip(ip_address_nmap, file_name, last_processed):
    start_time = time.time()
    suspicious_ips = [ip.strip() for ip in ip_address_nmap.split(",")]

    results = {}
    for ip in suspicious_ips:
        print(f"\n🔍 Scanning {ip}...")

        scan_data = {
            "mac_address": None,
            "device_name": "Unknown",
            "os": None,
            "location": None
        }

        # Nmap scan
        try:
            nmap_output = subprocess.check_output(["sudo", "nmap", "-O", "-sS", "-Pn", ip], universal_newlines=True)

            mac_match = re.search(r"MAC Address: ([0-9A-F:]+)", nmap_output)
            if mac_match:
                scan_data["mac_address"] = mac_match.group(1)

            device_match = re.search(r"MAC Address: [0-9A-F:]+ \((.*?)\)", nmap_output)
            if device_match:
                scan_data["device_name"] = device_match.group(1)

            os_match = re.search(r"OS details: (.+)", nmap_output)
            if os_match:
                scan_data["os"] = os_match.group(1)

        except subprocess.CalledProcessError as e:
            scan_data["error"] = f"Scan failed: {e}"

        # Location
        location_info = get_ip_location(ip)
        if location_info.get("error") == "private range":
            print("🛡️ Private IP detected. Getting public IP location...")
            public_ip = subprocess.check_output(["curl", "-s", "ipinfo.io/ip"], text=True).strip()
            print(f"🌐 Public IP: {public_ip}")
            public_location = get_ip_location(public_ip)
            scan_data["location"] = public_location
        else:
            scan_data["location"] = location_info

        results[ip] = scan_data

    # Save scan results
    output_path = "/home/mahesh/mahesh2003/project/json log/nmap_results.json"
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=4)

    print(f"\n✅ All results saved to: {output_path}")
    print(f"⏱️ Scan completed in {time.time() - start_time:.2f} seconds.")

    # Combine with other logs
    combine_all_logs_and_save(file_name, ip_address_nmap, last_processed)

# Function to combine logs and save the final result
def combine_all_logs_and_save(file_name, ip_address_nmap, last_processed):
    print(f"🔄 Updating final result for: {file_name} with IP: {ip_address_nmap}")

    output_path =JSON_PATH

    # Load existing results if available
    if os.path.exists(output_path):
        with open(output_path, "r") as f:
            contents = f.read().strip()
            final_results = json.loads(contents) if contents else {}
    else:
        final_results = {}

    attack_data = {}

    try:
        with open(file_paths[file_name], "r") as f:
            contents = f.read().strip()
            if not contents:
                print(f"[Warning] Skipping {file_name} during final merge (empty file).")
                return
            data = json.loads(contents)

            if file_name == "ZeroDay_suspicious_ips.json":
                latest_ip = max(data.items(), key=lambda item: parse_timestamp(item[1]["timestamp"]))
                ip = latest_ip[0]
                attack_data = {
                    **latest_ip[1],
                    "source_ip": ip,
                    "type_attack": file_name
                }
            else:
                latest = max(data, key=lambda x: parse_timestamp(x["timestamp"]))
                attack_data = {**latest, "type_attack": file_name}

    except Exception as e:
        print(f"[Error] Failed to extract from {file_name}: {e}")
        return

    # Load Nmap data
    try:
        with open("/home/mahesh/mahesh2003/project/json log/nmap_results.json", "r") as f:
            contents = f.read().strip()
            nmap_data = json.loads(contents) if contents else {}
            scan_data = nmap_data.get(attack_data.get("source_ip", ""), {})
    except Exception as e:
        print(f"[Error] Failed to load Nmap data: {e}")
        scan_data = {}

    # Merge and update only that IP
    if attack_data:
        source_ip = attack_data.get("source_ip")
        if source_ip:
            final_results[source_ip] = {
                **scan_data,
                **attack_data
            }

    # Save
    with open(output_path, "w") as f:
        json.dump(final_results, f, indent=4)

    print(f"✅ Final output saved to: {output_path}")


def is_installed(cmd):
    """Check if a command is installed on the system."""
    return shutil.which(cmd) is not None

def update_json(ip_address, status):
    """Update the JSON file with IP block status."""
    if not os.path.exists(JSON_PATH):
        print(f"[!] JSON file not found at {JSON_PATH}")
        return

    try:
        with open(JSON_PATH, "r") as f:
            data = json.load(f)

        if ip_address in data:
            data[ip_address]["ip_blocked"] = str(status).lower()
        else:
            # Attempt to match by source_ip field
            for key in data:
                if data[key].get("source_ip") == ip_address:
                    data[key]["ip_blocked"] = str(status).lower()
                    break
            else:
                print(f"[!] IP {ip_address} not found in JSON data.")
                return

        with open(JSON_PATH, "w") as f:
            json.dump(data, f, indent=4)
        print(f"[+] Updated JSON log for {ip_address} -> ip_blocked: {status}")

    except Exception as e:
        print(f"[!] Error updating JSON file: {e}")

def block_ip_nft(ip_address):
    try:
        # Create table if it doesn't exist
        subprocess.run(["sudo", "nft", "list tables"], check=False, capture_output=True)
        tables = subprocess.run(["sudo", "nft", "list tables"], capture_output=True, text=True).stdout
        if "blocklist" not in tables:
            print("[+] Creating nftables table 'blocklist'...")
            subprocess.run(["sudo", "nft", "add", "table", "inet", "blocklist"], check=False)

        # Create input and output chains if they don't exist
        chains = subprocess.run(["sudo", "nft", "list chains", "inet", "blocklist"], capture_output=True, text=True).stdout
        if "input" not in chains:
            print("[+] Creating 'input' chain...")
            subprocess.run([
                "sudo", "nft", "add", "chain", "inet", "blocklist", "input", 
                "{", "type", "filter", "hook", "input", "priority", "0", ";", "}"], check=False)

        if "output" not in chains:
            print("[+] Creating 'output' chain...")
            subprocess.run([
                "sudo", "nft", "add", "chain", "inet", "blocklist", "output", 
                "{", "type", "filter", "hook", "output", "priority", "0", ";", "}"], check=False)

        # Add rule to block incoming traffic from the IP
        print(f"[+] Blocking incoming traffic from IP {ip_address}...")
        subprocess.run(["sudo", "nft", "add", "rule", "inet", "blocklist", "input", 
                        "ip", "saddr", ip_address, "drop"], check=True)

        # Add rule to block outgoing traffic to the IP
        print(f"[+] Blocking outgoing traffic to IP {ip_address}...")
        subprocess.run(["sudo", "nft", "add", "rule", "inet", "blocklist", "output", 
                        "ip", "daddr", ip_address, "drop"], check=True)

        print(f"[?] Blocked IP {ip_address} completely (both incoming and outgoing) using nftables.")
        update_json(ip_address, True)
    
    except subprocess.CalledProcessError as e:
        print(f"[?] Failed to block IP {ip_address} using nftables. Error: {e}")
        update_json(ip_address, False)

def block_ip_iptables(ip_address):
    try:
        print("[+] Blocking with iptables...")

        # Block incoming traffic from the IP
        print(f"[+] Blocking incoming traffic from IP {ip_address}...")
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)

        # Block outgoing traffic to the IP
        print(f"[+] Blocking outgoing traffic to IP {ip_address}...")
        subprocess.run(["sudo", "iptables", "-A", "OUTPUT", "-d", ip_address, "-j", "DROP"], check=True)

        print(f"[?] Blocked IP {ip_address} completely (both incoming and outgoing) using iptables.")
        update_json(ip_address, True)

    except subprocess.CalledProcessError as e:
        print(f"[?] Failed to block IP {ip_address} using iptables. Error: {e}")
        update_json(ip_address, False)

def ip_blocker(ip_blocker_input):
    ip = ip_blocker_input.strip()
    
    if is_installed("nft"):
        block_ip_nft(ip)
    elif is_installed("iptables"):
        block_ip_iptables(ip)
    else:
        print("[!] Neither nftables nor iptables is installed on this system.")
        update_json(ip, False)


# === Message Formatter ===
def send_alert_from_file():
    result = subprocess.run(["/home/mahesh/mahesh2003/project/myenv/bin/python", "/home/mahesh/mahesh2003/project/Telegram_and_goip_nmap/Telegram_alert.py"], capture_output=True, text=True)
    print(result.stdout)


# Initialize the last_processed dictionary globally
last_processed = {}

# Get directory to watch
watch_dir = "/home/mahesh/mahesh2003/project/json log"

# Start the watchdog observer
observer = Observer()
event_handler = LogFileHandler()
observer.schedule(event_handler, watch_dir, recursive=False)
observer.start()
# === MAIN LOOP ===

print(f"🔍 Watching log files in: {watch_dir}")
try:
    while True:
        time.sleep(0.5)
except KeyboardInterrupt:
    observer.stop()
observer.join()