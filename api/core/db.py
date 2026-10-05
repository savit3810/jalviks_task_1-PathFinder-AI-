import motor.motor_asyncio
import os
import asyncio
from datetime import datetime, timezone
from core.config import settings

MONGO_URI = settings.MONGO_URI
client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URI, serverSelectionTimeoutMS=2000)
db = client.pathfinder

async def get_db():
    return db

async def save_prediction(user_id: str, profile_type: str, input_data: dict, prediction_result: dict):
    try:
        collection = db.user_predictions
        record = {
            "user_id": user_id,
            "profile_type": profile_type,
            "input_data": input_data,
            "prediction": prediction_result,
            "timestamp": datetime.now(timezone.utc)
        }
        await collection.insert_one(record)
        return True
    except Exception:
        # Avoid printing verbose errors to stdout in production
        return False

async def get_user_history(user_id: str):
    try:
        collection = db.user_predictions
        cursor = collection.find({"user_id": user_id}).sort("timestamp", -1)
        history = await cursor.to_list(length=100)
        for h in history:
            h["_id"] = str(h["_id"])
        return history
    except Exception:
        return []
