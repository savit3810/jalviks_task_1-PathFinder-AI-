# Compliance Matrix

This matrix maps every assignment requirement to the specific implementation and evidence location.

## Section 3.1 — Secure Authentication & Access Control

| Requirement | Implementation | Location |
|-------------|---------------|----------|
| Login and logout | POST `/api/auth/login`, POST `/api/auth/logout` | `api/routers/auth.py` |
| RBAC with ≥3 roles | 7 roles: admin, class10, class12, college, graduate, parent, viewer | `api/schemas/user.py` (role pattern), `api/core/dependencies.py` |
| MFA for admin | TOTP via pyotp, Fernet-encrypted secrets | `api/routers/auth.py` (L122-204), `api/core/security.py` |
| Account lockout | 5 failures → 15 min lockout | `api/routers/auth.py` (L71-80) |
| RS256 JWT ≤15 min | RS256, 10-minute expiry | `api/core/security.py` (L42-62), `api/core/config.py` |
| Secure refresh tokens | SHA-256 hashed, HttpOnly cookie, rotation, reuse detection | `api/routers/auth.py` (L206-262) |
| Server-side authorization | `require_roles()` dependency on all protected endpoints | `api/core/dependencies.py` |
| No hardcoded credentials | CLI admin bootstrap, `.env` auto-generated | `api/app/cli.py`, `scripts/gen-secrets.sh` |
| Demo: low-priv can't access admin | Test suite verifies viewer/student get 403 on admin endpoints | `tests/security/test_security.py`, `evidence/SECURITY_TESTING_EVIDENCE.md` |

## Section 3.2 — API & Application Security

| Requirement | Implementation | Location |
|-------------|---------------|----------|
| SQL/NoSQL Injection protection | Pydantic EmailStr + extra="forbid" + Motor typed queries | `api/schemas/user.py`, `api/schemas/ml.py` |
| XSS protection | React DOM escaping + CSP + WAF pattern blocking | `nginx/waf.conf` (L64-74), `api/app/main.py` (L34) |
| Broken Access Control | `require_roles()` + admin CIDR restriction | `api/core/dependencies.py`, `api/routers/admin.py` |
| Brute-force protection | Account lockout + Nginx rate limiting (5r/s login) | `api/routers/auth.py`, `nginx/waf.conf` (L2, L87-88) |
| Server-side input validation | Pydantic v2 Field validators (ge, le, pattern, min_length, max_length) | `api/schemas/ml.py`, `api/schemas/user.py` |
| Parameterized queries / ORM | Motor async driver with Python dict queries | `api/routers/auth.py`, `api/routers/ml.py` |
| Content Security Policy | `default-src 'self'; script-src 'self' ...` | `nginx/waf.conf` (L42), `api/app/main.py` (L34) |
| HSTS | `max-age=31536000; includeSubDomains; preload` | `nginx/waf.conf` (L36), `api/app/main.py` (L37) |
| X-Frame-Options | `DENY` | `nginx/waf.conf` (L37), `api/app/main.py` (L36) |
| X-Content-Type-Options | `nosniff` | `nginx/waf.conf` (L38), `api/app/main.py` (L35) |
| Generic error messages | Global exception handler with request_id | `api/app/main.py` (L42-50) |

## Section 3.3 — Network & Deployment Security

| Requirement | Implementation | Location |
|-------------|---------------|----------|
| Multi-tier architecture | WAF → App → DB with 3 Docker networks | `docker-compose.yml` |
| Reverse proxy | Nginx with TLS termination and WAF rules | `nginx/waf.conf`, `nginx/Dockerfile` |
| HTTPS | TLS 1.2/1.3, HTTP→HTTPS redirect | `nginx/waf.conf` (L14-19, L26-34) |
| Only required ports exposed | Only 80/443 on host | `docker-compose.yml` (L19-21) |
| DB not internet-accessible | MongoDB on `internal: true` network | `docker-compose.yml` (L9-11, L97-120) |
| Firewall/network restrictions | `internal: true` networks + UFW script | `docker-compose.yml`, `scripts/firewall-ufw.sh` |
| Admin access restricted | CIDR-based IP restriction on admin endpoints | `api/routers/admin.py` |
| Architecture diagram | Full network topology with communication paths | `docs/security/ARCHITECTURE_DIAGRAM.md` |

## Section 3.4 — Security Logging & Attack Detection

| Requirement | Implementation | Location |
|-------------|---------------|----------|
| Successful login | `LOGIN_SUCCESS` event | `api/routers/auth.py` (L119) |
| Failed login | `LOGIN_FAILURE` event | `api/routers/auth.py` (L64, L79) |
| Account lockout | `ACCOUNT_LOCKED` event | `api/routers/auth.py` (L76) |
| Unauthorized access | `UNAUTHORIZED_ACCESS` / `FORBIDDEN_ACCESS` events | `api/core/dependencies.py` (L32, L47) |
| Role/permission changes | `ROLE_CHANGE` event | `api/routers/admin.py` |
| Administrator activity | `ADMIN_ACTION` event for all admin operations | `api/routers/admin.py` |
| Configuration changes | `CONFIG_CHANGE` event | `api/routers/admin.py` |
| API errors | Global exception handler logs all errors | `api/app/main.py` (L42-50) |
| Data export/download | `DATA_EXPORT` event with record count | `api/routers/admin.py` |
| ≥3 Security alerts | 5 rules: brute force (account), brute force (IP), privilege escalation, token theft, excessive export | `api/core/alerts.py` |
| Backend-generated, stored events | Hash-chained MongoDB + JSONL backup | `api/core/logging.py` |

## Section 3.5 — DevSecOps Pipeline

| Requirement | Implementation | Location |
|-------------|---------------|----------|
| SAST | Semgrep (OWASP, Python, TS, React, JWT, Secrets) | `.github/workflows/security-pipeline.yml` (L16-32) |
| SCA | pip-audit + npm audit | `.github/workflows/security-pipeline.yml` (L34-52) |
| Secret scanning | Gitleaks with full history | `.github/workflows/security-pipeline.yml` (L54-66) |
| Container scanning | Trivy on frontend + backend images | `.github/workflows/security-pipeline.yml` (L68-94) |
| DAST | OWASP ZAP baseline scan | `.github/workflows/security-pipeline.yml` (L96-114) |
| HIGH/CRITICAL blocks build | `exit-code: 1`, `--severity ERROR --error`, `--audit-level=high` | `.github/workflows/security-pipeline.yml` |

## Section 4 — Security Testing (≥5 Tests)

| # | Test | Evidence |
|---|------|----------|
| 1 | RBAC: Viewer → Admin (403) | `evidence/SECURITY_TESTING_EVIDENCE.md` → Test 1 |
| 2 | Brute-force → Lockout (423) | `evidence/SECURITY_TESTING_EVIDENCE.md` → Test 2 |
| 3 | NoSQL injection → Rejected (422) | `evidence/SECURITY_TESTING_EVIDENCE.md` → Test 3 |
| 4 | XSS payload → Safe handling | `evidence/SECURITY_TESTING_EVIDENCE.md` → Test 4 |
| 5 | Forged JWT → Rejected (401) | `evidence/SECURITY_TESTING_EVIDENCE.md` → Test 5 |
| 6 | Security scan → Remediation | `evidence/SECURITY_TESTING_EVIDENCE.md` → Test 6 |
| Automated | 10+ pytest tests | `tests/security/test_security.py` |

## Section 6 — Deliverables

| Deliverable | Location |
|-------------|----------|
| Complete source code | This repository |
| README | `README.md` |
| Architecture diagram | `docs/security/ARCHITECTURE_DIAGRAM.md` |
| Security report | `docs/SECURITY_REPORT.md` |
| CI/CD pipeline | `.github/workflows/security-pipeline.yml` |
| Security testing evidence | `evidence/SECURITY_TESTING_EVIDENCE.md`, `tests/security/` |
| Docker configuration | `docker-compose.yml`, `Dockerfile`, `api/Dockerfile`, `nginx/Dockerfile` |
