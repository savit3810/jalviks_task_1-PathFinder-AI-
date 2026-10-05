from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from schemas.user import UserCreate, UserLogin, TokenResponse, MFASetupResponse, MFAVerify
from core.security import (
    get_password_hash, verify_password, dummy_verify,
    create_access_token, create_refresh_token, hash_refresh_token,
    generate_mfa_secret, get_totp_uri, verify_totp, encrypt_mfa_secret, decrypt_mfa_secret,
    get_private_key, get_public_key
)
from core.db import get_db
from core.logging import SecurityAuditLogger
import uuid
import jwt
from core.config import settings
from datetime import datetime, timezone, timedelta
import os

router = APIRouter()

async def get_audit_logger():
    db = await get_db()
    return SecurityAuditLogger(db)

@router.post("/signup", status_code=status.HTTP_201_CREATED)
async def signup(user_in: UserCreate, request: Request, db=Depends(get_db), logger=Depends(get_audit_logger)):
    collection = db.users
    existing = await collection.find_one({"email": user_in.email.lower()})
    if existing:
        await logger.log_event("SIGNUP_FAILURE", "low", "failure", request.state.req_id if hasattr(request.state, 'req_id') else str(uuid.uuid4()), source_ip=request.client.host, details={"reason": "Email already exists"})
        raise HTTPException(status_code=400, detail="Email already registered")

    user_id = str(uuid.uuid4())
    hashed_password = get_password_hash(user_in.password)
    
    new_user = {
        "id": user_id,
        "name": user_in.name,
        "email": user_in.email.lower(),
        "password": hashed_password,
        "role": user_in.role,
        "linkedChildCode": user_in.linkedChildCode,
        "careerGoal": user_in.careerGoal,
        "mfa_enabled": False,
        "mfa_secret": None,
        "failed_logins": 0,
        "locked_until": None,
        "created_at": datetime.now(timezone.utc)
    }
    await collection.insert_one(new_user)
    
    await logger.log_event("USER_CREATED", "info", "success", str(uuid.uuid4()), actor_user_id=user_id, actor_role=user_in.role, source_ip=request.client.host)
    
    return {"message": "User created successfully"}

@router.post("/login", response_model=TokenResponse)
async def login(credentials: UserLogin, request: Request, response: Response, db=Depends(get_db), logger=Depends(get_audit_logger)):
    req_id = str(uuid.uuid4())
    collection = db.users
    user = await collection.find_one({"email": credentials.email.lower()})
    
    now = datetime.now(timezone.utc)
    
    if not user:
        dummy_verify()
        await logger.log_event("LOGIN_FAILURE", "medium", "failure", req_id, source_ip=request.client.host, details={"reason": "Invalid credentials"})
        raise HTTPException(status_code=401, detail="Invalid email or password")
        
    if user.get("locked_until") and user["locked_until"].replace(tzinfo=timezone.utc) > now:
        await logger.log_event("LOGIN_FAILURE", "medium", "failure", req_id, actor_user_id=user["id"], source_ip=request.client.host, details={"reason": "Account locked"})
        raise HTTPException(status_code=423, detail="Account is locked. Please try again later.")
        
    if not verify_password(credentials.password, user["password"]):
        failed_logins = user.get("failed_logins", 0) + 1
        updates = {"failed_logins": failed_logins}
        if failed_logins >= 5:
            updates["locked_until"] = now + timedelta(minutes=15)
            await logger.log_event("ACCOUNT_LOCKED", "high", "success", req_id, actor_user_id=user["id"], source_ip=request.client.host)
            
        await collection.update_one({"_id": user["_id"]}, {"$set": updates})
        await logger.log_event("LOGIN_FAILURE", "medium", "failure", req_id, actor_user_id=user["id"], source_ip=request.client.host, details={"reason": "Invalid credentials"})
        raise HTTPException(status_code=401, detail="Invalid email or password")
        
    # Reset failed logins
    if user.get("failed_logins", 0) > 0:
        await collection.update_one({"_id": user["_id"]}, {"$set": {"failed_logins": 0, "locked_until": None}})
        
    # MFA Check
    if user.get("mfa_enabled") and user.get("mfa_secret"):
        key = get_private_key()
        alg = "RS256" if "BEGIN" in key else "HS256"
        mfa_token = jwt.encode({"sub": user["id"], "type": "mfa_pending", "exp": now + timedelta(minutes=5)}, key, algorithm=alg)
        return {"access_token": "", "mfa_required": True, "mfa_token": mfa_token}
        
    # Generate tokens
    access_token = create_access_token(user["id"], user["role"])
    refresh_token = create_refresh_token()
    
    # Store refresh token family
    rt_hash = hash_refresh_token(refresh_token)
    await db.refresh_tokens.insert_one({
        "user_id": user["id"],
        "token_hash": rt_hash,
        "family_id": str(uuid.uuid4()),
        "expires_at": now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        "revoked": False,
        "ip": request.client.host,
        "user_agent": request.headers.get("user-agent", "")
    })
    
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/api/auth",
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
    )
    
    await logger.log_event("LOGIN_SUCCESS", "info", "success", req_id, actor_user_id=user["id"], actor_role=user["role"], source_ip=request.client.host)
    return {"access_token": access_token}

@router.post("/mfa/setup")
async def setup_mfa(request: Request, db=Depends(get_db), logger=Depends(get_audit_logger)):
    """Admin or any user can enrol in MFA. Requires a valid access token."""
    from core.dependencies import require_roles
    # Inline auth check
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = auth_header.split(" ", 1)[1]
    try:
        key = get_public_key()
        alg = "RS256" if "BEGIN" in key else "HS256"
        payload = jwt.decode(token, key, algorithms=[alg], audience="pathfinder-client", issuer="pathfinder-api")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user_id = payload.get("sub")
    user = await db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.get("mfa_enabled"):
        raise HTTPException(status_code=400, detail="MFA already enabled")
    
    secret = generate_mfa_secret()
    uri = get_totp_uri(secret, user["email"])
    encrypted = encrypt_mfa_secret(secret)
    
    await db.users.update_one({"_id": user["_id"]}, {"$set": {"mfa_secret": encrypted, "mfa_enabled": True}})
    await logger.log_event("MFA_ENROLLED", "info", "success", str(uuid.uuid4()), actor_user_id=user_id, source_ip=request.client.host)
    
    return {"secret": secret, "provisioning_uri": uri}

@router.post("/mfa/verify", response_model=TokenResponse)
async def verify_mfa(mfa_data: MFAVerify, request: Request, response: Response, db=Depends(get_db), logger=Depends(get_audit_logger)):
    req_id = str(uuid.uuid4())
    try:
        key = get_private_key()
        alg = "RS256" if "BEGIN" in key else "HS256"
        payload = jwt.decode(mfa_data.mfa_token, key, algorithms=[alg])
        if payload.get("type") != "mfa_pending":
            raise ValueError()
        user_id = payload.get("sub")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid MFA token")
        
    user = await db.users.find_one({"id": user_id})
    if not user or not user.get("mfa_secret"):
        raise HTTPException(status_code=401, detail="MFA not setup")
        
    secret = decrypt_mfa_secret(user["mfa_secret"])
    if not verify_totp(secret, mfa_data.code):
        await logger.log_event("MFA_FAILURE", "medium", "failure", req_id, actor_user_id=user_id, source_ip=request.client.host)
        raise HTTPException(status_code=401, detail="Invalid MFA code")
        
    # Success
    access_token = create_access_token(user["id"], user["role"])
    refresh_token = create_refresh_token()
    rt_hash = hash_refresh_token(refresh_token)
    now = datetime.now(timezone.utc)
    
    await db.refresh_tokens.insert_one({
        "user_id": user["id"],
        "token_hash": rt_hash,
        "family_id": str(uuid.uuid4()),
        "expires_at": now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        "revoked": False,
        "ip": request.client.host,
        "user_agent": request.headers.get("user-agent", "")
    })
    
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/api/auth",
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
    )
    
    await logger.log_event("MFA_SUCCESS", "info", "success", req_id, actor_user_id=user_id, source_ip=request.client.host)
    await logger.log_event("LOGIN_SUCCESS", "info", "success", req_id, actor_user_id=user_id, actor_role=user["role"], source_ip=request.client.host)
    return {"access_token": access_token}

@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(request: Request, response: Response, db=Depends(get_db), logger=Depends(get_audit_logger)):
    req_id = str(uuid.uuid4())
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Missing refresh token")
        
    rt_hash = hash_refresh_token(refresh_token)
    token_record = await db.refresh_tokens.find_one({"token_hash": rt_hash})
    
    if not token_record:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
        
    if token_record.get("revoked"):
        # REUSE DETECTED! Revoke all tokens in family
        await db.refresh_tokens.update_many(
            {"family_id": token_record["family_id"]},
            {"$set": {"revoked": True}}
        )
        await logger.log_event("REFRESH_TOKEN_REUSE_DETECTED", "critical", "failure", req_id, actor_user_id=token_record["user_id"], source_ip=request.client.host)
        raise HTTPException(status_code=401, detail="Token revoked")
        
    if token_record["expires_at"].replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Token expired")
        
    # Rotate token
    await db.refresh_tokens.update_one({"_id": token_record["_id"]}, {"$set": {"revoked": True}})
    
    user = await db.users.find_one({"id": token_record["user_id"]})
    if not user or user.get("locked_until") and user["locked_until"].replace(tzinfo=timezone.utc) > datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Account unavailable")
        
    new_access = create_access_token(user["id"], user["role"])
    new_refresh = create_refresh_token()
    
    await db.refresh_tokens.insert_one({
        "user_id": user["id"],
        "token_hash": hash_refresh_token(new_refresh),
        "family_id": token_record["family_id"],
        "expires_at": datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        "revoked": False,
        "ip": request.client.host,
        "user_agent": request.headers.get("user-agent", "")
    })
    
    response.set_cookie(
        key="refresh_token",
        value=new_refresh,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/api/auth",
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
    )
    
    await logger.log_event("TOKEN_REFRESHED", "info", "success", req_id, actor_user_id=user["id"], source_ip=request.client.host)
    return {"access_token": new_access}

@router.post("/logout")
async def logout(request: Request, response: Response, db=Depends(get_db), logger=Depends(get_audit_logger)):
    req_id = str(uuid.uuid4())
    refresh_token = request.cookies.get("refresh_token")
    if refresh_token:
        rt_hash = hash_refresh_token(refresh_token)
        token_record = await db.refresh_tokens.find_one({"token_hash": rt_hash})
        if token_record:
            await db.refresh_tokens.update_many(
                {"family_id": token_record["family_id"]},
                {"$set": {"revoked": True}}
            )
            await logger.log_event("LOGOUT", "info", "success", req_id, actor_user_id=token_record["user_id"], source_ip=request.client.host)
            
    response.delete_cookie("refresh_token", path="/api/auth")
    return {"message": "Logged out successfully"}
