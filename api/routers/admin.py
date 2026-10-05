from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from core.dependencies import require_roles, get_audit_logger
from core.db import get_db
from core.config import settings
from core.logging import SecurityAuditLogger
from pydantic import BaseModel, Field
import ipaddress
import json
import io
import uuid

router = APIRouter()


# ── Schemas ──────────────────────────────────────────────────────────────────
class RoleChangeRequest(BaseModel):
    user_id: str = Field(..., min_length=1)
    new_role: str = Field(..., pattern="^(class10|class12|college|graduate|parent|viewer)$")

    class Config:
        extra = "forbid"


class ConfigChangeRequest(BaseModel):
    key: str = Field(..., pattern="^(ADMIN_ALLOWED_CIDRS|ACCESS_TOKEN_EXPIRE_MINUTES|REFRESH_TOKEN_EXPIRE_DAYS)$")
    value: str = Field(..., min_length=1, max_length=200)

    class Config:
        extra = "forbid"


# ── Admin IP restriction ─────────────────────────────────────────────────────
def verify_admin_cidr(request: Request):
    client_ip = request.client.host
    allowed_cidrs = [cidr.strip() for cidr in settings.ADMIN_ALLOWED_CIDRS.split(",")]

    is_allowed = False
    try:
        ip = ipaddress.ip_address(client_ip)
        for cidr in allowed_cidrs:
            if ip in ipaddress.ip_network(cidr):
                is_allowed = True
                break
    except ValueError:
        pass

    if not is_allowed:
        raise HTTPException(status_code=403, detail="Admin access denied from this IP")


# ── List Users ────────────────────────────────────────────────────────────────
@router.get("/users", dependencies=[Depends(require_roles(["admin"]))])
async def list_users(
    request: Request,
    limit: int = 50,
    skip: int = 0,
    db=Depends(get_db),
    logger: SecurityAuditLogger = Depends(get_audit_logger)
):
    verify_admin_cidr(request)
    cursor = db.users.find(
        {},
        {"_id": 0, "password": 0, "mfa_secret": 0}
    ).sort("created_at", -1).skip(skip).limit(limit)
    users = await cursor.to_list(length=limit)

    await logger.log_event(
        "ADMIN_ACTION", "info", "success",
        request.state.req_id,
        actor_user_id=request.state.user["sub"],
        actor_role="admin",
        source_ip=request.client.host,
        details={"action": "Listed users", "count": len(users), "limit": limit, "skip": skip}
    )
    return {"users": users, "count": len(users)}


# ── Change User Role ──────────────────────────────────────────────────────────
@router.put("/users/role", dependencies=[Depends(require_roles(["admin"]))])
async def change_user_role(
    role_change: RoleChangeRequest,
    request: Request,
    db=Depends(get_db),
    logger: SecurityAuditLogger = Depends(get_audit_logger)
):
    verify_admin_cidr(request)
    user = await db.users.find_one({"id": role_change.user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    old_role = user.get("role")
    if old_role == "admin":
        raise HTTPException(status_code=400, detail="Cannot change role of an admin user")

    if old_role == role_change.new_role:
        raise HTTPException(status_code=400, detail="User already has this role")

    await db.users.update_one(
        {"id": role_change.user_id},
        {"$set": {"role": role_change.new_role}}
    )

    await logger.log_event(
        "ROLE_CHANGE", "high", "success",
        request.state.req_id,
        actor_user_id=request.state.user["sub"],
        actor_role="admin",
        target=role_change.user_id,
        source_ip=request.client.host,
        details={
            "action": "Changed user role",
            "old_role": old_role,
            "new_role": role_change.new_role
        }
    )

    return {"message": f"Role changed from '{old_role}' to '{role_change.new_role}'"}


# ── View Audit Logs ───────────────────────────────────────────────────────────
@router.get("/audit", dependencies=[Depends(require_roles(["admin"]))])
async def get_audit_logs(
    request: Request,
    limit: int = 50,
    skip: int = 0,
    event_type: str = None,
    db=Depends(get_db),
    logger: SecurityAuditLogger = Depends(get_audit_logger)
):
    verify_admin_cidr(request)

    query = {}
    if event_type:
        query["event_type"] = event_type

    cursor = db.security_events.find(query, {"_id": 0}).sort("timestamp", -1).skip(skip).limit(limit)
    logs = await cursor.to_list(length=limit)

    await logger.log_event(
        "ADMIN_ACTION", "info", "success",
        request.state.req_id,
        actor_user_id=request.state.user["sub"],
        actor_role="admin",
        source_ip=request.client.host,
        details={"action": "Viewed audit logs", "limit": limit, "filter": event_type}
    )
    return logs


# ── View Security Alerts ──────────────────────────────────────────────────────
@router.get("/alerts", dependencies=[Depends(require_roles(["admin"]))])
async def get_security_alerts(
    request: Request,
    db=Depends(get_db),
    logger: SecurityAuditLogger = Depends(get_audit_logger)
):
    verify_admin_cidr(request)
    cursor = db.security_alerts.find({}, {"_id": 0}).sort("first_seen", -1).limit(50)
    alerts = await cursor.to_list(length=50)

    await logger.log_event(
        "ADMIN_ACTION", "info", "success",
        request.state.req_id,
        actor_user_id=request.state.user["sub"],
        actor_role="admin",
        source_ip=request.client.host,
        details={"action": "Viewed security alerts", "count": len(alerts)}
    )
    return alerts


# ── Acknowledge Alert ─────────────────────────────────────────────────────────
@router.put("/alerts/{rule_id}/acknowledge", dependencies=[Depends(require_roles(["admin"]))])
async def acknowledge_alert(
    rule_id: str,
    request: Request,
    db=Depends(get_db),
    logger: SecurityAuditLogger = Depends(get_audit_logger)
):
    verify_admin_cidr(request)
    result = await db.security_alerts.update_one(
        {"rule_id": rule_id, "status": "open"},
        {"$set": {"status": "acknowledged"}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="No open alert found with this rule ID")

    await logger.log_event(
        "ADMIN_ACTION", "info", "success",
        request.state.req_id,
        actor_user_id=request.state.user["sub"],
        actor_role="admin",
        source_ip=request.client.host,
        details={"action": "Acknowledged alert", "rule_id": rule_id}
    )
    return {"message": f"Alert '{rule_id}' acknowledged"}


# ── Configuration Change ─────────────────────────────────────────────────────
@router.put("/config", dependencies=[Depends(require_roles(["admin"]))])
async def update_config(
    config_change: ConfigChangeRequest,
    request: Request,
    db=Depends(get_db),
    logger: SecurityAuditLogger = Depends(get_audit_logger)
):
    verify_admin_cidr(request)

    # Store config in DB for audit trail (runtime configs)
    old_config = await db.app_config.find_one({"key": config_change.key})
    old_value = old_config["value"] if old_config else "default"

    await db.app_config.update_one(
        {"key": config_change.key},
        {"$set": {"key": config_change.key, "value": config_change.value}},
        upsert=True
    )

    await logger.log_event(
        "CONFIG_CHANGE", "high", "success",
        request.state.req_id,
        actor_user_id=request.state.user["sub"],
        actor_role="admin",
        source_ip=request.client.host,
        details={
            "action": "Configuration updated",
            "key": config_change.key,
            "old_value": old_value,
            "new_value": config_change.value
        }
    )

    return {"message": f"Configuration '{config_change.key}' updated"}


# ── Data Export (with logging) ────────────────────────────────────────────────
@router.get("/export/users", dependencies=[Depends(require_roles(["admin"]))])
async def export_users(
    request: Request,
    db=Depends(get_db),
    logger: SecurityAuditLogger = Depends(get_audit_logger)
):
    verify_admin_cidr(request)

    cursor = db.users.find(
        {},
        {"_id": 0, "password": 0, "mfa_secret": 0}
    )
    users = await cursor.to_list(length=10000)

    await logger.log_event(
        "DATA_EXPORT", "high", "success",
        request.state.req_id,
        actor_user_id=request.state.user["sub"],
        actor_role="admin",
        source_ip=request.client.host,
        details={
            "action": "Exported user data",
            "records_exported": len(users),
            "export_format": "JSON"
        }
    )

    content = json.dumps(users, indent=2, default=str)
    return StreamingResponse(
        io.BytesIO(content.encode()),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=users_export.json"}
    )


@router.get("/export/audit-logs", dependencies=[Depends(require_roles(["admin"]))])
async def export_audit_logs(
    request: Request,
    db=Depends(get_db),
    logger: SecurityAuditLogger = Depends(get_audit_logger)
):
    verify_admin_cidr(request)

    cursor = db.security_events.find({}, {"_id": 0}).sort("timestamp", -1)
    logs = await cursor.to_list(length=10000)

    await logger.log_event(
        "DATA_EXPORT", "high", "success",
        request.state.req_id,
        actor_user_id=request.state.user["sub"],
        actor_role="admin",
        source_ip=request.client.host,
        details={
            "action": "Exported audit logs",
            "records_exported": len(logs),
            "export_format": "JSON"
        }
    )

    content = json.dumps(logs, indent=2, default=str)
    return StreamingResponse(
        io.BytesIO(content.encode()),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=audit_logs_export.json"}
    )
