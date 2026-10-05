# Architecture Diagram

## Network Topology

```
┌──────────────────────────────────────────────────────────────────────┐
│                         INTERNET                                      │
│                            │                                          │
│                       Port 80/443                                     │
│                            │                                          │
│  ┌─────────────────────────▼──────────────────────────────────────┐  │
│  │          EDGE NETWORK (pathfinder_edge)                         │  │
│  │                                                                 │  │
│  │   ┌──────────────────────────────────────────┐                  │  │
│  │   │  WAF / Reverse Proxy                     │                  │  │
│  │   │  (Nginx + ModSecurity OWASP CRS)         │                  │  │
│  │   │                                          │                  │  │
│  │   │  • TLS Termination (TLSv1.2/1.3)         │                  │  │
│  │   │  • HTTP → HTTPS redirect                 │                  │  │
│  │   │  • Security Headers (HSTS, CSP, etc.)    │                  │  │
│  │   │  • OWASP Core Rule Set (SQLi, XSS, etc.) │                  │  │
│  │   │  • Rate Limiting                         │                  │  │
│  │   └──────────────┬───────────┬───────────────┘                  │  │
│  │                  │           │                                   │  │
│  └──────────────────│───────────│───────────────────────────────────┘  │
│                     │           │                                      │
│  ┌──────────────────▼───────────▼───────────────────────────────────┐ │
│  │          APP NETWORK (pathfinder_app) — Internal Only             │ │
│  │                                                                   │ │
│  │   ┌─────────────────────┐   ┌──────────────────────────────┐     │ │
│  │   │  Frontend           │   │  Backend API                 │     │ │
│  │   │  (Nginx + React SPA)│   │  (FastAPI / Uvicorn)         │     │ │
│  │   │                     │   │                              │     │ │
│  │   │  • Static assets    │   │  • RS256 JWT Auth            │     │ │
│  │   │  • Read-only FS     │   │  • Argon2id Passwords        │     │ │
│  │   │  • No direct access │   │  • RBAC (admin/student/etc.) │     │ │
│  │   │                     │   │  • TOTP MFA                  │     │ │
│  │   └─────────────────────┘   │  • Refresh Token Rotation    │     │ │
│  │                             │  • Account Lockout (5 fails)  │     │ │
│  │                             │  • Tamper-evident Audit Logs  │     │ │
│  │                             │  • Alert Engine               │     │ │
│  │                             │  • Pydantic Input Validation  │     │ │
│  │                             │  • Safe Pickle Loader         │     │ │
│  │                             └──────────────┬───────────────┘     │ │
│  │                                            │                     │ │
│  └────────────────────────────────────────────│─────────────────────┘ │
│                                               │                       │
│  ┌────────────────────────────────────────────▼─────────────────────┐ │
│  │          DB NETWORK (pathfinder_db) — Internal Only               │ │
│  │                                                                   │ │
│  │   ┌──────────────────────────────┐                               │ │
│  │   │  MongoDB 6.0                 │                               │ │
│  │   │                              │                               │ │
│  │   │  • No internet exposure      │                               │ │
│  │   │  • Auth required             │                               │ │
│  │   │  • Persistent volume         │                               │ │
│  │   │  • Stores: users, tokens,    │                               │ │
│  │   │    security_events, alerts   │                               │ │
│  │   └──────────────────────────────┘                               │ │
│  │                                                                   │ │
│  └───────────────────────────────────────────────────────────────────┘ │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
```

## Communication Paths

| From | To | Protocol | Purpose |
|------|----|----------|---------|
| Internet | WAF | HTTPS (443) | User access |
| Internet | WAF | HTTP (80) | Redirects to HTTPS |
| WAF | Frontend | HTTP (internal) | Serve React SPA |
| WAF | Backend | HTTP (internal) | Proxy `/api/*` requests |
| Backend | MongoDB | TCP 27017 (internal) | Data persistence |

## Security Controls Per Layer

| Layer | Controls |
|-------|----------|
| **Edge (WAF)** | TLS termination, OWASP ModSecurity CRS, rate limiting, security headers |
| **Application** | JWT RS256 auth, RBAC, MFA (TOTP), account lockout, input validation, CSP, HSTS |
| **Database** | Internal network only, authenticated access, no internet exposure |
| **Container** | Non-root users, read-only filesystems, capability drops, memory limits, no-new-privileges |
