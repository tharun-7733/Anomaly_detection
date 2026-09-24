#!/bin/bash
# AWS EC2 Setup Script for Anomaly Detection Backend

# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install Python and PCAP library (needed for Scapy sniffing)
sudo apt-get install -y python3 python3-pip libpcap-dev python3-venv

# Navigate to backend directory and install Python dependencies globally for root
cd backend
sudo pip3 install -r requirements.txt --break-system-packages --ignore-installed

# Start the server with sudo (Requires sudo for raw socket packet sniffing)
echo "Setup complete! To run the backend, execute:"
echo "sudo python3 api.py"
