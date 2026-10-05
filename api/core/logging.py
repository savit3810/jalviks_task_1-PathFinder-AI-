import json
import hashlib
from datetime import datetime, timezone
import os
import uuid

def canonical_json(data: dict) -> str:
    # Sort keys to ensure deterministic JSON representation
    return json.dumps(data, sort_keys=True, separators=(',', ':'))

class SecurityAuditLogger:
    def __init__(self, db):
        self.db = db
        self.collection = db.get_collection("security_events")
        # Ensure log file dir exists
        os.makedirs("/app/logs", exist_ok=True)
        self.log_file = "/app/logs/security.jsonl"
    
    async def log_event(
        self,
        event_type: str,
        severity: str,
        outcome: str,
        request_id: str,
        actor_user_id: str = None,
        actor_role: str = None,
        target: str = None,
        source_ip: str = None,
        user_agent: str = None,
        method: str = None,
        path: str = None,
        status_code: int = None,
        details: dict = None
    ):
        # Fetch previous hash to form the chain
        last_event = await self.collection.find_one({}, sort=[("timestamp", -1)])
        prev_hash = last_event["hash"] if last_event and "hash" in last_event else "GENESIS"
        
        record = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "severity": severity,
            "outcome": outcome,
            "actor_user_id": actor_user_id,
            "actor_role": actor_role,
            "target": target,
            "source_ip": source_ip,
            "user_agent": user_agent,
            "request_id": request_id,
            "method": method,
            "path": path,
            "status_code": status_code,
            "details": details or {},
            "prev_hash": prev_hash
        }
        
        # Calculate current hash
        raw_to_hash = prev_hash + canonical_json(record)
        current_hash = hashlib.sha256(raw_to_hash.encode()).hexdigest()
        record["hash"] = current_hash
        
        # Insert into MongoDB
        await self.collection.insert_one(record.copy())
        
        # Write to local file
        record.pop("_id", None)
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(record) + "\n")
        except Exception:
            pass # Fallback if file system not writable
            
        return record["event_id"]
