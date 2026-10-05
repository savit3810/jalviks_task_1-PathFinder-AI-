# PathFinder AI — Secured Application

PathFinder AI is an intelligent career guidance application built with React, FastAPI, and MongoDB. This repository contains the **fully secured version** implementing comprehensive cybersecurity controls including RS256 JWT authentication, RBAC, MFA, WAF protection, tamper-evident audit logging, and a full DevSecOps pipeline.

---

## Table of Contents
- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [User Roles](#user-roles)
- [API Endpoints](#api-endpoints)
- [Running Security Tests](#running-security-tests)
- [Running Security Scans](#running-security-scans)
- [Viewing Audit Logs & Alerts](#viewing-audit-logs--alerts)
- [CI/CD Pipeline](#cicd-pipeline)
- [Project Structure](#project-structure)
- [Security Controls Summary](#security-controls-summary)

---

## Features

### Security
- **RS256 JWT Authentication** — Asymmetric RSA-2048 signed tokens with 10-minute expiry
- **Argon2id Password Hashing** — Winner of the Password Hashing Competition
- **TOTP Multi-Factor Authentication** — Required for admin accounts (Google Authenticator compatible)
- **Role-Based Access Control (RBAC)** — 7 distinct roles with server-side enforcement
- **Account Lockout** — 15-minute lockout after 5 failed login attempts
- **Refresh Token Rotation** — SHA-256 hashed, HttpOnly cookies with reuse detection
- **Tamper-Evident Audit Logs** — SHA-256 hash-chained security events in MongoDB + JSONL backup
- **5 Alert Rules** — Brute force, privilege escalation, token theft, excessive export detection
- **WAF** — Nginx reverse proxy with SQLi/XSS pattern blocking, rate limiting, and security headers
- **Container Hardening** — Read-only filesystems, non-root users, capability drops, memory limits

### Application
- ML-powered career predictions (Class 10 → Stream, Class 12 → Course, College → Domain)
- Salary projection with 5-year growth forecast
- Alumni matching engine
- Career lifecycle roadmaps

---

## Architecture

```
Internet → HTTPS (443) → Nginx WAF → [Frontend SPA | Backend API] → MongoDB
```

Three isolated Docker networks enforce segmentation:
- **`pathfinder_edge`** — Internet-facing (WAF only)
- **`pathfinder_app`** — Internal (Frontend + Backend, no internet access)
- **`pathfinder_db`** — Internal (Backend + MongoDB only)

Only ports **80** and **443** are exposed. MongoDB (27017) and Backend (8000) are never directly reachable.

> See `docs/security/ARCHITECTURE_DIAGRAM.md` for the full network topology diagram.

---

## Prerequisites

| Requirement | Version |
|------------|---------|
| Docker | 20.10+ |
| Docker Compose | 2.0+ |
| OpenSSL | 1.1+ (for certificate/key generation) |
| Bash | 4.0+ (for setup scripts) |
| Git | 2.0+ |

**Optional (for local development/testing):**
| Requirement | Version |
|------------|---------|
| Python | 3.10+ |
| Node.js | 20+ |
| npm | 9+ |

---

## Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/your-repo/PathFinder-AI-Secured.git
cd PathFinder-AI-Secured
```

### 2. Generate TLS Certificates
```bash
make certs
# or manually:
bash scripts/gen-certs.sh
```
This creates a self-signed certificate at `nginx/ssl/server.crt` and `nginx/ssl/server.key`.

### 3. Generate Secrets (RSA Keys, Passwords, Fernet Key)
```bash
make secrets
# or manually:
bash scripts/gen-secrets.sh
```
This generates:
- RSA-2048 key pair at `api/secrets/private.pem` and `api/secrets/public.pem`
- `.env` file with random MongoDB password and Fernet encryption key

### 4. Start the Docker Stack
```bash
make up
# or manually:
docker-compose up -d
```

### 5. Bootstrap the Admin Account
```bash
docker exec -it pathfinder_backend python app/cli.py create-admin
```
You will be prompted for:
- **Admin Email** — any valid email address
- **Admin Password** — minimum 12 characters (entered via secure prompt, not echoed)

### 6. Access the Application
| URL | Description |
|-----|-------------|
| `https://localhost` | Frontend application (accept the self-signed cert warning) |
| `http://localhost` | Auto-redirects to HTTPS |

> **Note:** The backend API (`http://localhost:8000`) is NOT directly accessible from the host. All API calls go through the WAF at `https://localhost/api/`.

---

## Configuration

### Environment Variables (`.env`)
| Variable | Description | Default |
|----------|-------------|---------|
| `MONGO_INITDB_ROOT_USERNAME` | MongoDB admin username | `admin` |
| `MONGO_INITDB_ROOT_PASSWORD` | MongoDB admin password | *(auto-generated)* |
| `APP_ENV` | Application environment | `production` |
| `JWT_PRIVATE_KEY_PATH` | Path to RSA private key | `/app/secrets/private.pem` |
| `JWT_PUBLIC_KEY_PATH` | Path to RSA public key | `/app/secrets/public.pem` |
| `JWT_ALGORITHM` | JWT signing algorithm | `RS256` |
| `FERNET_KEY` | Encryption key for MFA secrets | *(auto-generated)* |
| `ADMIN_ALLOWED_CIDRS` | CIDRs allowed for admin endpoints | `127.0.0.1/32,172.16.0.0/12,...` |

> **Important:** No hardcoded credentials exist. All passwords and keys are generated at deployment time.

---

## User Roles

| Role | Description | Can Access |
|------|-------------|-----------|
| `admin` | System administrator (MFA required) | Everything + audit logs, alerts, user management, exports |
| `class10` | Class 10 student | ML predictions, lifecycle data, alumni matching |
| `class12` | Class 12 student | ML predictions, lifecycle data, alumni matching |
| `college` | College student | ML predictions, salary projection, alumni matching |
| `graduate` | Graduate | ML predictions, salary projection |
| `parent` | Parent/guardian | Linked child's data (read-only) |
| `viewer` | Read-only viewer | Public endpoints only |

---

## API Endpoints

### Authentication (`/api/auth/`)
| Method | Endpoint | Auth Required | Description |
|--------|----------|--------------|-------------|
| POST | `/api/auth/signup` | No | Register a new user |
| POST | `/api/auth/login` | No | Login (returns JWT or MFA challenge) |
| POST | `/api/auth/mfa/setup` | Yes | Enable TOTP MFA |
| POST | `/api/auth/mfa/verify` | MFA Token | Complete MFA login |
| POST | `/api/auth/refresh` | Cookie | Rotate refresh token |
| POST | `/api/auth/logout` | Cookie | Revoke session |

### Admin (`/api/admin/`) — Admin role only
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/admin/users` | List all users (passwords excluded) |
| PUT | `/api/admin/users/role` | Change a user's role |
| GET | `/api/admin/audit` | View audit log events |
| GET | `/api/admin/alerts` | View security alerts |
| PUT | `/api/admin/alerts/{id}/acknowledge` | Acknowledge an alert |
| PUT | `/api/admin/config` | Update runtime configuration |
| GET | `/api/admin/export/users` | Export user data (JSON download) |
| GET | `/api/admin/export/audit-logs` | Export audit logs (JSON download) |

### ML Predictions (`/api/`) — Any authenticated user
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/predict/stream` | Class 10 → Stream prediction |
| POST | `/api/predict/course` | Class 12 → Course prediction |
| POST | `/api/seniors/match` | Alumni matching |
| GET | `/api/health` | Health check (public) |

---

## Running Security Tests

### Prerequisites
```bash
pip install pytest httpx pytest-asyncio
```

### Run All Security Tests
```bash
# Ensure Docker stack is running first
make up

# Run tests
make test
# or:
pytest tests/security/ -v --tb=short
```

### Test Coverage
The test suite (`tests/security/test_security.py`) covers:
1. **RBAC enforcement** — viewer/student cannot access admin endpoints
2. **Brute-force lockout** — 5 wrong passwords lock the account
3. **NoSQL injection** — MongoDB operators rejected by Pydantic
4. **XSS payloads** — script tags safely handled
5. **JWT validation** — forged/expired/tampered tokens rejected
6. **Input validation** — out-of-range values rejected
7. **Security headers** — HSTS, CSP, X-Frame-Options present
8. **Password policy** — weak passwords rejected
9. **Generic errors** — no information leakage in error messages
10. **Duplicate prevention** — duplicate email registration blocked

---

## Running Security Scans

### SAST (Static Analysis)
```bash
make scan-sast
# Runs: semgrep scan --config=p/owasp-top-ten --config=p/python --config=p/typescript
```

### SCA (Dependency Scanning)
```bash
make scan-sca
# Runs: pip-audit + npm audit
```

### Container Scanning
```bash
# Build images first
docker build -t pathfinder-frontend:latest -f Dockerfile .
docker build -t pathfinder-backend:latest -f api/Dockerfile api/

# Scan with Trivy
trivy image pathfinder-frontend:latest --severity HIGH,CRITICAL
trivy image pathfinder-backend:latest --severity HIGH,CRITICAL
```

### Secret Scanning
```bash
gitleaks detect --source . --config .gitleaks.toml
```

### DAST (Dynamic Scanning)
```bash
# Start the stack
make up
# Run OWASP ZAP baseline
docker run -t zaproxy/zap-stable zap-baseline.py -t https://localhost -a
```

---

## Viewing Audit Logs & Alerts

### Via Admin API
```bash
# Get an admin JWT token first
TOKEN=$(curl -s -k https://localhost/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"YourPassword123!"}' \
  | jq -r '.access_token')

# View audit logs
curl -s -k https://localhost/api/admin/audit \
  -H "Authorization: Bearer $TOKEN" | jq

# View security alerts
curl -s -k https://localhost/api/admin/alerts \
  -H "Authorization: Bearer $TOKEN" | jq
```

### Via Docker Logs
```bash
# View backend application logs
docker logs pathfinder_backend

# View JSONL audit log file
docker exec pathfinder_backend cat /app/logs/security.jsonl | jq
```

### Via MongoDB Direct Query
```bash
docker exec -it pathfinder_mongo mongosh -u admin -p <password> pathfinder \
  --eval "db.security_events.find().sort({timestamp:-1}).limit(10).pretty()"
```

---

## CI/CD Pipeline

The GitHub Actions pipeline (`.github/workflows/security-pipeline.yml`) runs on:
- Every push to `main`
- Every pull request to `main`
- Nightly at 02:00 UTC

### Pipeline Stages
| Stage | Tool | Blocks on |
|-------|------|-----------|
| SAST | Semgrep | ERROR severity findings |
| SCA | pip-audit + npm audit | HIGH+ vulnerabilities |
| Secret Scanning | Gitleaks | Any hardcoded secrets |
| Container Scan | Trivy | HIGH/CRITICAL CVEs |
| DAST | OWASP ZAP | Baseline scan alerts |
| **Security Gate** | — | Any upstream failure |

---

## Project Structure

```
├── .github/workflows/
│   └── security-pipeline.yml    # CI/CD security pipeline
├── api/
│   ├── app/
│   │   ├── main.py              # FastAPI application entry point
│   │   └── cli.py               # Admin bootstrap CLI
│   ├── core/
│   │   ├── alerts.py            # Background alert engine (5 rules)
│   │   ├── config.py            # Application configuration
│   │   ├── db.py                # MongoDB connection
│   │   ├── dependencies.py      # JWT auth + RBAC dependencies
│   │   ├── logging.py           # Tamper-evident audit logger
│   │   ├── model_loader.py      # Safe pickle loader with SHA-256
│   │   └── security.py          # JWT, Argon2id, TOTP, Fernet
│   ├── routers/
│   │   ├── admin.py             # Admin endpoints (users, roles, config, export)
│   │   ├── auth.py              # Auth endpoints (login, signup, MFA, refresh)
│   │   └── ml.py                # ML prediction endpoints
│   ├── schemas/
│   │   ├── ml.py                # Pydantic ML input schemas
│   │   └── user.py              # Pydantic auth schemas
│   ├── secrets/                 # RSA key pair (generated, not committed)
│   ├── Dockerfile               # Backend container (non-root, read-only)
│   └── requirements.txt         # Python dependencies
├── docs/
│   ├── SECURITY_REPORT.md       # Full security report (9 sections)
│   └── security/
│       ├── ARCHITECTURE_DIAGRAM.md
│       ├── COMPLIANCE_MATRIX.md
│       └── 00-baseline-findings.md
├── evidence/                    # Security test evidence
├── nginx/
│   ├── waf.conf                 # WAF config (rate limiting, headers, patterns)
│   ├── Dockerfile               # WAF container
│   └── ssl/                     # TLS certificates (generated, not committed)
├── scripts/
│   ├── gen-certs.sh             # TLS certificate generation
│   ├── gen-secrets.sh           # RSA keys + .env generation
│   └── firewall-ufw.sh         # Host firewall setup
├── tests/security/
│   ├── test_security.py         # Comprehensive security test suite (10+ tests)
│   └── test_rbac.py             # Basic RBAC tests
├── docker-compose.yml           # Multi-tier deployment (3 networks)
├── Dockerfile                   # Frontend container (multi-stage build)
├── Makefile                     # Build, test, and scan commands
└── .gitleaks.toml               # Secret scanning configuration
```

---

## Security Controls Summary

| Category | Control | Implementation |
|----------|---------|---------------|
| **Authentication** | RS256 JWT (10 min) | `api/core/security.py` |
| **Password** | Argon2id + 12-char minimum | `api/core/security.py`, `api/schemas/user.py` |
| **MFA** | TOTP with Fernet-encrypted secrets | `api/routers/auth.py` |
| **Authorization** | RBAC with 7 roles | `api/core/dependencies.py` |
| **Account Protection** | Lockout after 5 failures (15 min) | `api/routers/auth.py` |
| **Token Security** | Refresh rotation + reuse detection | `api/routers/auth.py` |
| **Input Validation** | Pydantic v2 strict schemas | `api/schemas/` |
| **Injection Prevention** | Typed queries + extra="forbid" | All schemas |
| **XSS Prevention** | React DOM + CSP + WAF patterns | Frontend + `nginx/waf.conf` |
| **Security Headers** | HSTS, X-Frame-Options, CSP, etc. | `nginx/waf.conf` + `api/app/main.py` |
| **Rate Limiting** | 5r/s login, 20r/s API, 30r/s general | `nginx/waf.conf` |
| **Network Isolation** | 3 Docker networks (edge/app/db) | `docker-compose.yml` |
| **Container Security** | Non-root, read-only FS, cap drops | `docker-compose.yml` + Dockerfiles |
| **Audit Logging** | Hash-chained events in MongoDB + JSONL | `api/core/logging.py` |
| **Alerting** | 5 detection rules, 60s polling | `api/core/alerts.py` |
| **CI/CD Security** | SAST, SCA, Secrets, Containers, DAST | `.github/workflows/security-pipeline.yml` |

> **No hardcoded credentials exist in this repository.** All passwords and keys are generated at deployment time.
