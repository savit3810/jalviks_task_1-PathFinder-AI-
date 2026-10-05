#!/bin/bash
# Generate self-signed certificates for local HTTPS testing
set -e

mkdir -p nginx/ssl
cd nginx/ssl

if [ ! -f server.crt ]; then
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout server.key -out server.crt \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
    echo "Certificates generated in nginx/ssl"
else
    echo "Certificates already exist."
fi
