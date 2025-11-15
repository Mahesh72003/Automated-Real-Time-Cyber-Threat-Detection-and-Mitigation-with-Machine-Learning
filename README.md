# Automated Real-Time Cyber Threat Detection and Mitigation with Machine Learning

## 📘 Overview

This project provides an end-to-end system for **real-time network
monitoring**, **machine learning--based attack detection**, and
**automated mitigation**. It is designed for **home networks** and
**small businesses**, and runs efficiently on **Raspberry Pi**.

------------------------------------------------------------------------

## 📂 Project Structure

    Automated-Real-Time-Cyber-Threat-Detection-and-Mitigation-with-Machine-Learning/
    │
    ├── Dataset/                               # All datasets used for training & testing
    │   ├── CICIDS_2017/                        # CICIDS2017 CSV files (DDoS, PortScan, Web Attacks…)
    │   ├── Sql quary/                          # SQL Injection synthetic datasets
    │   └── UNSW-NB15/                          # UNSW-NB15 dataset (train/test)
    │
    ├── Module_Training/                        # All ML training modules & model files
    │   ├── bruteforce_Attack/                  # Brute force detection models & training script
    │   ├── DDOS_Attack/                        # DDoS detection models (large pkl & scaler)
    │   ├── SQL_injection/                      # SQLi classifier + vectorizer
    │   └── Zero_exploration/                   # Zero-Day hybrid models + large dataset
    │
    ├── json log/                               # Generated log files during live detection
    │   ├── ddos_log_live.csv
    │   ├── finial_result.json
    │   ├── ZeroDay_suspicious_flows_log.json
    │   └── threat_log.json
    │
    ├── Graph pic/                              # ML evaluation graphs & visualization
    │   ├── brute_force_feature_importance.png
    │   ├── ddos_cluster_visualization.png
    │   └── Sql_injuction_Matrix.png
    │
    ├── myenv/                                  # Virtual environment (Python 3.11 + packages)
    │
    └── README.md                               

------------------------------------------------------------------------

## 🚀 Features

-   Live packet capture (PyShark/TShark)
-   ML-powered detection (DDoS, Bruteforce, SQL Injection, Zero-Day)
-   Auto-mitigation using iptables/nftables
-   Live alerting (Telegram + Email)
-   Real-time logs
-   Raspberry Pi optimized
-   Supports multiple datasets & models

------------------------------------------------------------------------

## 🛠 Installation

### **1. Update Raspberry Pi**

```bash
sudo apt update && sudo apt upgrade -y
```

### **2. Install Tshark**

```bash
sudo apt install tshark -y
sudo usermod -aG wireshark $USER
```

### **3. Install Firewall Tools (iptables & nftables)**

Both are required since the mitigation engine can use either one depending on your configuration.

```bash
sudo apt install iptables nftables -y
```

Enable nftables service (recommended):

```bash
sudo systemctl enable nftables
sudo systemctl start nftables
```

Check versions:

```bash
iptables --version
nft --version
```

------------------------------------------------------------------------

## ⚙️ Configuration

### **Telegram Token and Chat Id**  

    Telegram_and_goip_nmap/Telegram_alert.py

------------------------------------------------------------------------
### ⚠️ Important Note

**You MUST change this path** to match your project location:

```
/home/mahesh/mahesh2003/project
```
**Example:**
````
/home/yourusername/yourprojectfolder

````
Replace it with **your own absolute project path** before running.

Make sure the path correctly points to the directory that contains:
````
myenv/
src/
Dataset/
Module_Training/

````
------------------------------------------------------------------------
## ▶️ Running the System

This project includes a pre-configured script named **`start_tmux.sh`** that automatically:

* Activates the `myenv` virtual environment
* Starts a tmux session
* Runs the real-time detection engine
* Keeps the system running in the background

### **Run the project**

```bash
chmod +x start_tmux.sh
./start_tmux.sh
```

### **Reattach to the running tmux session**

```bash
tmux attach -t mysession
```

### **Stop the system**

Inside tmux:

```
CTRL + B, then X, then Y
```
------------------------------------------------------------------------

## 🔥 Testing Attacks

### DDoS simulation

    hping3 --flood --sync <target-ip>

------------------------------------------------------------------------

## 🧪 Logs

Stored in:

    json log/

------------------------------------------------------------------------

## 📄 License

This project is licensed under the MIT License.




