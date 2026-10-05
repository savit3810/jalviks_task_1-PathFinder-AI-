import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    APP_ENV: str = "production"
    MONGO_URI: str = "mongodb://admin:secret@mongo:27017/pathfinder?authSource=admin"
    
    JWT_PRIVATE_KEY_PATH: str = "/app/secrets/private.pem"
    JWT_PUBLIC_KEY_PATH: str = "/app/secrets/public.pem"
    JWT_ALGORITHM: str = "RS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 10
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    FERNET_KEY: str = ""
    
    ADMIN_ALLOWED_CIDRS: str = "127.0.0.1/32,172.16.0.0/12,192.168.0.0/16,10.0.0.0/8"

    class Config:
        env_file = ".env"

settings = Settings()
