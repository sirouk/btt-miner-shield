#!/bin/bash

# Check if an IP address is provided as an argument
if [ -z "$1" ]; then
    echo "Usage: $0 <IP_ADDRESS>"
    exit 1
fi

# Assign the first argument to IP_ADDRESS
IP_ADDRESS="$1"
while sudo netstat -an | grep ESTABLISHED | grep "$IP_ADDRESS"; do sudo iptables -A INPUT -s $IP_ADDRESS -j DROP; sudo conntrack -D --orig-src $IP_ADDRESS; sudo ss --kill -tn "dst == $IP_ADDRESS"; done
