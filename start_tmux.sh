#!/bin/bash

# Check if tmux is installed
if ! command -v tmux &> /dev/null
then
    echo "tmux could not be found. Please install tmux."
    exit 1
fi

# Start a new tmux session (detached) with a name and run the command
sudo tmux new-session -s mysession -d 'cd /home/mahesh/mahesh2003/project && sudo myenv/bin/active'

# Check if the tmux session started successfully
if [ $? -eq 0 ]; then
    echo "Tmux session started successfully."
else
    echo "Failed to start tmux session."
    exit 1
fi

# Attach to the tmux session to see what’s running
sudo tmux attach-session -t mysession


