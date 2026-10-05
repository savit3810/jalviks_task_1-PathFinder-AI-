from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from core.config import settings
from core.db import get_db
from core.logging import SecurityAuditLogger
from core.security import get_public_key
import uuid

security = HTTPBearer()

async def get_audit_logger():
    db = await get_db()
    return SecurityAuditLogger(db)

def require_roles(allowed_roles: list[str]):
    async def role_checker(
        request: Request,
        credentials: HTTPAuthorizationCredentials = Depends(security),
        db = Depends(get_db),
        logger: SecurityAuditLogger = Depends(get_audit_logger)
    ):
        req_id = getattr(request.state, "req_id", str(uuid.uuid4()))
        request.state.req_id = req_id
        
        token = credentials.credentials
        try:
            key = get_public_key()
            alg = "RS256" if "BEGIN" in key else "HS256"
            payload = jwt.decode(token, key, algorithms=[alg], audience="pathfinder-client", issuer="pathfinder-api")
        except jwt.ExpiredSignatureError:
            await logger.log_event("UNAUTHORIZED_ACCESS", "medium", "failure", req_id, source_ip=request.client.host, details={"reason": "Token expired"})
            raise HTTPException(status_code=401, detail="Token expired")
        except jwt.InvalidTokenError:
            await logger.log_event("UNAUTHORIZED_ACCESS", "medium", "failure", req_id, source_ip=request.client.host, details={"reason": "Invalid token"})
            raise HTTPException(status_code=401, detail="Invalid token")

        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
            
        user_role = payload.get("role")
        user_id = payload.get("sub")
        
        request.state.user = payload

        if allowed_roles and user_role not in allowed_roles:
            await logger.log_event("FORBIDDEN_ACCESS", "medium", "failure", req_id, actor_user_id=user_id, actor_role=user_role, source_ip=request.client.host, details={"reason": "Role not allowed", "allowed": allowed_roles})
            raise HTTPException(status_code=403, detail="Not enough permissions")
            
        # Denylist check (if we had redis, we'd check jti here, for now it's stateless access token with short expiry)
            
        return payload
    return role_checker

async def get_current_user(payload: dict = Depends(require_roles([]))):
    return payload
