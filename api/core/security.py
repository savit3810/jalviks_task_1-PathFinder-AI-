import jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from typing import Optional, Union, Any
from core.config import settings
import os
import pyotp
from cryptography.fernet import Fernet
import hashlib

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        return False

def dummy_verify():
    # Defend against timing attacks
    pwd_context.hash("dummy_password")

def get_private_key():
    path = settings.JWT_PRIVATE_KEY_PATH
    if not os.path.exists(path):
        # Fallback for local testing if not generated
        return "fallback-secret"
    with open(path, "r") as f:
        return f.read()

def get_public_key():
    path = settings.JWT_PUBLIC_KEY_PATH
    if not os.path.exists(path):
        # Fallback
        return "fallback-secret"
    with open(path, "r") as f:
        return f.read()

def create_access_token(subject: Union[str, Any], role: str, expires_delta: Optional[timedelta] = None) -> str:
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode = {
        "exp": expire,
        "nbf": datetime.now(timezone.utc) - timedelta(seconds=10),
        "iat": datetime.now(timezone.utc),
        "sub": str(subject),
        "role": role,
        "type": "access",
        "jti": os.urandom(16).hex(),
        "iss": "pathfinder-api",
        "aud": "pathfinder-client"
    }
    key = get_private_key()
    alg = settings.JWT_ALGORITHM if "BEGIN" in key else "HS256"
    encoded_jwt = jwt.encode(to_encode, key, algorithm=alg)
    return encoded_jwt

def create_refresh_token() -> str:
    return os.urandom(32).hex()

def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

def get_fernet():
    key = settings.FERNET_KEY
    if not key or key == "GENERATE_ME":
        # Only use this fallback in extreme cases, otherwise it errors out
        key = Fernet.generate_key()
    return Fernet(key)

def encrypt_mfa_secret(secret: str) -> str:
    f = get_fernet()
    return f.encrypt(secret.encode()).decode()

def decrypt_mfa_secret(encrypted_secret: str) -> str:
    f = get_fernet()
    return f.decrypt(encrypted_secret.encode()).decode()

def generate_mfa_secret() -> str:
    return pyotp.random_base32()

def get_totp_uri(secret: str, email: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name="PathFinder AI")

def verify_totp(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)
