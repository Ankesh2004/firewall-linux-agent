#!/bin/bash

# Detect the first non-loopback network interface
interface=$(ip -o -4 addr show up | grep -v '127.0.0.1' | awk '{print $2}' | head -n 1)

# Check if an interface was found
if [ -z "$interface" ]; then
    echo "No network interface found."
    exit 1
fi

# Update the configuration file
echo "interface=$interface" > config/network.conf

echo "Network interface set to $interface in config/network.conf"