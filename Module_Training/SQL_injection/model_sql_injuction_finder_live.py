import re
import joblib
import pandas as pd
import scapy.all as scapy
import urllib.parse
import json
import os
import numpy as np
from scipy.sparse import hstack, csr_matrix
import time

# Load the trained model and vectorizer
rf_classifier = joblib.load(r'/home/mahesh/mahesh2003/project/Module_Training/SQL_injection/sql_injection_classifier.pkl')
vectorizer = joblib.load(r'/home/mahesh/mahesh2003/project/Module_Training/SQL_injection/sql_injection_vectorizer.pkl')

# Log file path
log_file_path = r'/home/mahesh/mahesh2003/project/json log/sql_injection_log.json'

# Function to check if input is an email
def is_email(query):
    return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', query))

# Function to check if input is a username (basic heuristic)
def is_username(query):
    return bool(re.match(r'^[a-zA-Z0-9_]+$', query))

# Function to count special characters in input
def count_special_characters(query):
    special_chars = ["'", "\"", ";", "--", "#", "*", "(", ")", "@", "%"]
    return sum(query.count(char) for char in special_chars)

# Function to predict SQL injection attempts
def predict_sql_injection(user_input):
    if len(user_input) <= 20 and is_username(user_input):
        return False  # Assume safe if it matches a typical username pattern

    # Convert input to feature vector
    user_input_vec = vectorizer.transform([user_input])

    # Extract additional features
    special_char_count = count_special_characters(user_input)
    is_email_flag = int(is_email(user_input))
    is_username_flag = int(is_username(user_input))

    additional_features = csr_matrix([[special_char_count, is_email_flag, is_username_flag]])
    combined_features = hstack([user_input_vec, additional_features])

    # Adjust feature dimensions if necessary
    if combined_features.shape[1] != rf_classifier.n_features_in_:
        if combined_features.shape[1] > rf_classifier.n_features_in_:
            combined_features = combined_features[:, :rf_classifier.n_features_in_]
        else:
            padding = csr_matrix((combined_features.shape[0], rf_classifier.n_features_in_ - combined_features.shape[1]))
            combined_features = hstack([combined_features, padding])

    # Get prediction and ensure it's properly formatted
    prediction = rf_classifier.predict(combined_features)
    return bool(prediction[0]) if isinstance(prediction, (list, np.ndarray)) else bool(prediction)

# Function to detect SQL injection in network traffic
def detect_sql_injection(packet):
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
        raw_data = None
        if packet.haslayer(scapy.Raw):
            try:
                raw_data = packet[scapy.Raw].load.decode(errors="ignore")
            except UnicodeDecodeError:
                return  # Skip packets that can't be decoded
        
        if raw_data and "HTTP" in raw_data:
            post_data_match = re.search(r"^(POST|GET) .*? HTTP.*\r\n\r\n(.*)", raw_data, re.DOTALL)
            
            if post_data_match:
                post_data = urllib.parse.unquote(post_data_match.group(2))
                matches = re.findall(r"([a-zA-Z0-9_]+)=([^&]+)", post_data)
                source_ip = packet[scapy.IP].src

                # Dictionary to store detected SQL injection values
                sql_injection_data = {
                    "source_ip": str(source_ip),
                    "is_sql_injection": False  # Default is false, update if needed
                }
                current_time = time.strftime('%Y-%m-%d %H:%M:%S')
                for field, value in matches:
                    if not value.strip():
                        continue
                    
                    if field.lower() in ['username', 'password']:
                        is_injection = predict_sql_injection(value.strip())

                        if is_injection:
                            sql_injection_data["is_sql_injection"] = True
                            sql_injection_data[field] = value
                            sql_injection_data["timestamp"]= current_time

                # If SQL injection was detected in any field, log it
                if sql_injection_data["is_sql_injection"]:
                    # Ensure log directory exists
                    os.makedirs(os.path.dirname(log_file_path), exist_ok=True)

                    # Overwrite log file with detected SQL injection attempts
                    with open(log_file_path, 'w') as f:
                        json.dump([sql_injection_data], f, indent=4)

                    # Print the JSON output
                    print(json.dumps([sql_injection_data], indent=4))

                    return  # Exit after logging the detections

# Start live traffic monitoring
Interface ='wlan0'
print("Starting live traffic monitoring for SQL injection attempts...")
scapy.sniff(iface=Interface, prn=detect_sql_injection, store=False)
