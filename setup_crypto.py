import os
import uuid
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
from cryptography.fernet import Fernet

def main():
    print("Generating secrets and certificates...")
    
    # Generate .env
    env_path = ".env"
    if not os.path.exists(env_path):
        fernet_key = Fernet.generate_key().decode()
        mongo_pass = uuid.uuid4().hex
        env_content = f"""MONGO_INITDB_ROOT_USERNAME=admin
MONGO_INITDB_ROOT_PASSWORD={mongo_pass}
APP_ENV=production
JWT_PRIVATE_KEY_PATH=/app/secrets/private.pem
JWT_PUBLIC_KEY_PATH=/app/secrets/public.pem
JWT_ALGORITHM=RS256
FERNET_KEY={fernet_key}
"""
        with open(env_path, "w") as f:
            f.write(env_content)
        print(".env created.")

    # Generate RSA keys
    os.makedirs("api/secrets", exist_ok=True)
    private_key_path = "api/secrets/private.pem"
    public_key_path = "api/secrets/public.pem"
    
    if not os.path.exists(private_key_path):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        with open(private_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        public_key = private_key.public_key()
        with open(public_key_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print("RSA keys created.")

    # Generate X509 Certs
    os.makedirs("nginx/ssl", exist_ok=True)
    cert_path = "nginx/ssl/server.crt"
    key_path = "nginx/ssl/server.key"
    
    if not os.path.exists(cert_path):
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Organization"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).sign(key, hashes.SHA256())
        
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
            
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        print("Certificates created.")

if __name__ == "__main__":
    main()
