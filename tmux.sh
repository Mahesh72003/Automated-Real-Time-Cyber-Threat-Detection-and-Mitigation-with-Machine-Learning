#!/bin/bash

# Check if tmux is installed
if ! command -v tmux &> /dev/null
then
    echo "tmux could not be found. Please install tmux."
    exit 1
fi

# Start a new tmux session (detached) with a name
sudo tmux new-session -s mysession -d 'cd /home/mahesh/mahesh2003/project && source  myenv/bin/activate; bash'

# Create 5 windows in the tmux session with different names and commands

# 1. Ddos Attack Window
sudo tmux new-window -t mysession:1 -n 'Ddos' 'cd /home/mahesh/mahesh2003/project && source  myenv/bin/activate  &&  python3 /home/mahesh/mahesh2003/project/Module_Training/DDOS_Attack/model_ddos_attack_finder_live.py; bash'

# 2. SQL Injection Window
sudo tmux new-window -t mysession:2 -n 'SQL Injection' 'cd /home/mahesh/mahesh2003/project && source  myenv/bin/activate && python3 /home/mahesh/mahesh2003/project/Module_Training/SQL_injection/model_sql_injuction_finder_live.py; bash'

# 3. Brute Force Attack Window
sudo tmux new-window -t mysession:3 -n 'Brute Force Attack' 'cd /home/mahesh/mahesh2003/project && source  myenv/bin/activate && python3 /home/mahesh/mahesh2003/project/Module_Training/bruteforce_Attack/model_brute_force_finder_live.py; bash'

# 4. Zero-Day Exploit Window
sudo tmux new-window -t mysession:4 -n 'Zero-Day Exploit' 'cd /home/mahesh/mahesh2003/project && source  myenv/bin/activate && python3 /home/mahesh/mahesh2003/project/Module_Training/Zero_exploration/model_Zero_exploration_finder_live.py; bash'

#5 Telegram alert Window
sudo tmux new-window -t mysession:5 -n 'Telegram alert' 'cd /home/mahesh/mahesh2003/project && source  myenv/bin/activate && python3 /home/mahesh/mahesh2003/project/Telegram_and_goip_nmap/nmap_goip.py; bash'


# Check if the tmux session started successfully
if [ $? -eq 0 ]; then
    echo "Tmux session with 5 windows created successfully."
else
    echo "Failed to start tmux session."
    exit 1
fi

# Attach to the tmux session to see what’s running
sudo tmux attach-session -t mysession
