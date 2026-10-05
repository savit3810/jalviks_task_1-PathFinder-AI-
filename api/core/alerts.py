import asyncio
from datetime import datetime, timezone, timedelta
from core.db import get_db
import logging

class AlertEngine:
    def __init__(self, db):
        self.db = db
        self.events_coll = db.security_events
        self.alerts_coll = db.security_alerts

    async def evaluate_rules(self):
        try:
            now = datetime.now(timezone.utc)
            five_mins_ago = now - timedelta(minutes=5)
            ten_mins_ago = now - timedelta(minutes=10)
            
            # Rule 1: Brute force (5 failures per account in 5 mins)
            # This is already somewhat handled in login, but we can alert on it globally
            cursor = self.events_coll.aggregate([
                {"$match": {"event_type": "LOGIN_FAILURE", "timestamp": {"$gte": five_mins_ago.isoformat()}}},
                {"$group": {"_id": "$actor_user_id", "count": {"$sum": 1}, "ips": {"$addToSet": "$source_ip"}, "events": {"$push": "$event_id"}}},
                {"$match": {"count": {"$gte": 5}}}
            ])
            async for doc in cursor:
                if doc["_id"]: # If not null
                    await self._create_alert("rule_brute_force_account", "high", f"Brute force detected on account {doc['_id']}", doc["events"])

            # Rule 1b: Brute force from IP (10 failures per IP in 5 mins)
            cursor_ip = self.events_coll.aggregate([
                {"$match": {"event_type": "LOGIN_FAILURE", "timestamp": {"$gte": five_mins_ago.isoformat()}}},
                {"$group": {"_id": "$source_ip", "count": {"$sum": 1}, "events": {"$push": "$event_id"}}},
                {"$match": {"count": {"$gte": 10}}}
            ])
            async for doc in cursor_ip:
                if doc["_id"]:
                    await self._create_alert("rule_brute_force_ip", "high", f"Brute force detected from IP {doc['_id']}", doc["events"])

            # Rule 2: Repeated 403/401 (Privilege escalation)
            cursor_authz = self.events_coll.aggregate([
                {"$match": {"event_type": {"$in": ["UNAUTHORIZED_ACCESS", "FORBIDDEN_ACCESS"]}, "timestamp": {"$gte": ten_mins_ago.isoformat()}}},
                {"$group": {"_id": "$source_ip", "count": {"$sum": 1}, "events": {"$push": "$event_id"}}},
                {"$match": {"count": {"$gte": 5}}}
            ])
            async for doc in cursor_authz:
                if doc["_id"]:
                    await self._create_alert("rule_privilege_escalation", "medium", f"Repeated authorization failures from IP {doc['_id']}", doc["events"])

            # Rule 4: Refresh-token reuse / token anomaly
            cursor_token = self.events_coll.find({
                "event_type": "REFRESH_TOKEN_REUSE_DETECTED",
                "timestamp": {"$gte": five_mins_ago.isoformat()}
            })
            async for doc in cursor_token:
                await self._create_alert("rule_token_theft", "critical", f"Refresh token reuse detected for user {doc.get('actor_user_id')}", [doc["event_id"]])

            # Rule 5: Excessive data exports (3+ exports in 10 minutes)
            cursor_export = self.events_coll.aggregate([
                {"$match": {"event_type": "DATA_EXPORT", "timestamp": {"$gte": ten_mins_ago.isoformat()}}},
                {"$group": {"_id": "$actor_user_id", "count": {"$sum": 1}, "events": {"$push": "$event_id"}}},
                {"$match": {"count": {"$gte": 3}}}
            ])
            async for doc in cursor_export:
                if doc["_id"]:
                    await self._create_alert("rule_excessive_export", "high", f"Excessive data exports by user {doc['_id']}", doc["events"])

        except Exception as e:
            logging.error(f"Alert engine error: {e}")

    async def _create_alert(self, rule_id: str, severity: str, description: str, events: list):
        # Deduplicate
        existing = await self.alerts_coll.find_one({"rule_id": rule_id, "description": description, "status": "open"})
        if existing:
            await self.alerts_coll.update_one(
                {"_id": existing["_id"]},
                {"$set": {"last_seen": datetime.now(timezone.utc).isoformat()}, "$inc": {"count": 1}, "$addToSet": {"evidence_event_ids": {"$each": events}}}
            )
        else:
            await self.alerts_coll.insert_one({
                "rule_id": rule_id,
                "severity": severity,
                "description": description,
                "status": "open",
                "evidence_event_ids": events,
                "first_seen": datetime.now(timezone.utc).isoformat(),
                "last_seen": datetime.now(timezone.utc).isoformat(),
                "count": 1
            })

async def alert_scheduler():
    db = await get_db()
    engine = AlertEngine(db)
    while True:
        await engine.evaluate_rules()
        await asyncio.sleep(60) # Run every minute
