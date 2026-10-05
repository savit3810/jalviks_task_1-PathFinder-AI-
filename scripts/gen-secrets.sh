#!/bin/bash
# Generate secrets, RSA keys for JWT, and create .env file
set -e

mkdir -p api/secrets
cd api/secrets

if [ ! -f private.pem ]; then
    echo "Generating RSA key pair for JWT..."
    openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
    openssl rsa -pubout -in private.pem -out public.pem
    echo "RSA keys generated in api/secrets/"
fi

cd ../../

if [ ! -f .env ]; then
    echo "Creating .env file..."
    cat <<EOF > .env
# Database
MONGO_INITDB_ROOT_USERNAME=admin
MONGO_INITDB_ROOT_PASSWORD=$(openssl rand -hex 16)

# Application
APP_ENV=production
JWT_PRIVATE_KEY_PATH=/app/secrets/private.pem
JWT_PUBLIC_KEY_PATH=/app/secrets/public.pem
JWT_ALGORITHM=RS256

# Cryptography
FERNET_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" || echo "GENERATE_ME")
EOF
    echo ".env file created with random passwords."
else
    echo ".env file already exists."
fi
