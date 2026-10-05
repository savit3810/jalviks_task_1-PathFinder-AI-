import asyncio
import argparse
import sys
import uuid
import getpass
from datetime import datetime, timezone
import motor.motor_asyncio
import os
from passlib.context import CryptContext

# Basic configuration since we run this as a standalone script
MONGO_URI = os.getenv("MONGO_URI", "mongodb://admin:secret@localhost:27017/pathfinder?authSource=admin")
client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URI)
db = client.pathfinder

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

async def create_admin(force: bool):
    collection = db.users
    existing_admin = await collection.find_one({"role": "admin"})
    
    if existing_admin and not force:
        print("An admin already exists. Use --force to create another one.")
        sys.exit(1)
        
    print("Creating admin user...")
    email = input("Admin Email: ").strip()
    if not email:
        print("Email cannot be empty.")
        sys.exit(1)
        
    existing = await collection.find_one({"email": email.lower()})
    if existing:
        print("User with this email already exists.")
        sys.exit(1)
        
    password = getpass.getpass("Admin Password (min 12 chars): ")
    if len(password) < 12:
        print("Password must be at least 12 characters.")
        sys.exit(1)
        
    hashed_password = pwd_context.hash(password)
    user_id = str(uuid.uuid4())
    
    new_user = {
        "id": user_id,
        "name": "Administrator",
        "email": email.lower(),
        "password": hashed_password,
        "role": "admin",
        "linkedChildCode": None,
        "mfa_enabled": False, # Will be forced on first login because role is admin
        "mfa_secret": None,
        "failed_logins": 0,
        "locked_until": None,
        "created_at": datetime.now(timezone.utc)
    }
    await collection.insert_one(new_user)
    
    # Log it
    events_coll = db.security_events
    last_event = await events_coll.find_one({}, sort=[("timestamp", -1)])
    prev_hash = last_event["hash"] if last_event and "hash" in last_event else "GENESIS"
    
    import hashlib, json
    record = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "USER_CREATED",
        "severity": "info",
        "outcome": "success",
        "actor_user_id": "CLI",
        "actor_role": "system",
        "target": user_id,
        "source_ip": "127.0.0.1",
        "user_agent": "CLI",
        "request_id": str(uuid.uuid4()),
        "method": "CLI",
        "path": "create-admin",
        "status_code": 200,
        "details": {"role": "admin", "forced": force},
        "prev_hash": prev_hash
    }
    raw_to_hash = prev_hash + json.dumps(record, sort_keys=True, separators=(',', ':'))
    record["hash"] = hashlib.sha256(raw_to_hash.encode()).hexdigest()
    await events_coll.insert_one(record)
    
    print("Admin user created successfully.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PathFinder AI Admin Bootstrap")
    parser.add_argument("command", choices=["create-admin"], help="Command to run")
    parser.add_argument("--force", action="store_true", help="Force creation even if an admin exists")
    args = parser.parse_args()
    
    if args.command == "create-admin":
        asyncio.run(create_admin(args.force))
