import scapy.all as scapy
import re
import urllib.parse
from scapy.layers.http import HTTPRequest  # To capture HTTP Requests
from scapy.sendrecv import sniff

def detect_sql_injection(packet):
    if packet.haslayer(HTTPRequest):  # Process only HTTP requests
        raw_data = packet[scapy.Raw].load.decode(errors="ignore") if packet.haslayer(scapy.Raw) else None
        
        if raw_data:
            decoded_data = urllib.parse.unquote(raw_data)
            print(f"Raw Data from HTTP Request: {decoded_data}")  # For debugging

            matches = re.findall(r"(username|password|login|email|.*)=([^&]+)", decoded_data, re.IGNORECASE)

            for field, value in matches:
                if re.search(r"(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|UNION|EXEC|--|\s*;\s*)", value, re.IGNORECASE):
                    print(f"\nPossible SQL Injection Attempt Detected!\nSQL Injection Payload: {field}={value}\n")

print("Starting live traffic monitoring for SQL injection attempts...")
sniff(prn=detect_sql_injection, store=False)



