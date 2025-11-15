#!/bin/bash
sleep 2
# Start Wi-Fi Hotspot
sudo nmcli dev wifi hotspot ifname wlan0 ssid CyberSecurity password 'mahesh@2003'

# Wait a moment to make sure the hotspot is active (optional but helpful)
sleep 3

# Run the Python script
/usr/bin/python3 /home/mahesh/mahesh2003/ip_find_bot.py
