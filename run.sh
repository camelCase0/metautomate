#!/bin/bash

# Specify the network adapter
NET_ADAPTER="eth0"  # Replace with your network adapter (e.g., wlan0)

# Fetch the current IP address
IP_ADDRESS=$(ip -o -4 addr show $NET_ADAPTER | awk '{print $4}' | cut -d/ -f1)

# Check if IP_ADDRESS is non-empty
if [ -z "$IP_ADDRESS" ]; then
    echo "No IP address found for adapter $NET_ADAPTER"
    exit 1
fi

# API endpoint
URL="http://localhost:8000/scan"

# Send POST request
curl -X POST \
  -H "accept: application/json" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "fast_scan=false&scan_delay=&aggressive=false&ip_range=$IP_ADDRESS&retries=3&ping_scan=false&host_timeout=&os_detection=true&script=&service_version=true&max_rtt_timeout=&tcp_scan=false&udp_scan=false&port_range=" \
  "$URL"
