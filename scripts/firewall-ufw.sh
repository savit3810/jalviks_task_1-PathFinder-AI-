#!/bin/bash
# Provide firewall setup for network restrictions
# Run this on the host server

set -e

ADMIN_CIDR=${1:-"127.0.0.1/32"} # Default to localhost if not provided

echo "Configuring UFW firewall..."

# Default policies
ufw default deny incoming
ufw default allow outgoing

# Allow HTTP and HTTPS
ufw allow 80/tcp
ufw allow 443/tcp

# Allow SSH only from admin CIDR
ufw allow from $ADMIN_CIDR to any port 22

# Ensure MongoDB and Backend ports are not exposed on the host
ufw deny 27017/tcp
ufw deny 8000/tcp

echo "Enabling UFW..."
ufw --force enable

echo "Firewall configured successfully."
ufw status verbose
