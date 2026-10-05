from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from core.config import settings
import uuid
import logging

from routers.auth import router as auth_router
from routers.admin import router as admin_router
from routers.ml import router as ml_router
from core.alerts import alert_scheduler
import asyncio

app = FastAPI(
    title="PathFinder AI Secured Backend",
    docs_url="/docs" if settings.APP_ENV != "production" else None,
    redoc_url="/redoc" if settings.APP_ENV != "production" else None,
    openapi_url="/openapi.json" if settings.APP_ENV != "production" else None,
)

# CORS (Strict origin in production, but since this is local docker, we limit to frontend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://localhost", "http://localhost"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Security Headers Middleware
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["Cache-Control"] = "no-store"
    return response

# Global Exception Handler to prevent stack trace leaks
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    req_id = str(uuid.uuid4())
    # Log the full exception internally (we'd use proper logging here)
    logging.error(f"Request ID: {req_id} - Error: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "An internal server error occurred.", "request_id": req_id}
    )

# Routers
app.include_router(auth_router, prefix="/api/auth", tags=["auth"])
app.include_router(admin_router, prefix="/api/admin", tags=["admin"])
app.include_router(ml_router, prefix="/api", tags=["ml"])

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(alert_scheduler())

@app.get("/api/health")
async def health_check():
    return {"status": "ok"}
