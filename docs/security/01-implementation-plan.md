# Security Implementation Plan

## Phase 1: Cleanup and Docker Architecture
1. **Clean up artefacts**: Remove `dev_output.txt`, `api/import_test.txt`, `push_to_github.bat`, `vite.config.ts.timestamp-*.mjs`. Remove the legacy `frontend/` directory entirely (as permitted by instructions) to eliminate duplicate security surface.
2. **Dockerization & Networks**: Create `docker-compose.yml` with 3 isolated networks (`edge`, `app`, `db`).
3. **Nginx Reverse Proxy**: Add `nginx/nginx.conf` and ModSecurity WAF config.
4. **MongoDB**: Enable auth in mongo-init scripts. Create dedicated app user.

## Phase 2: Backend Authentication & Authorization (FastAPI)
1. **Restructure API**: Move from single `api/index.py` to `api/app/`, `api/core/`, `api/routers/`.
2. **Authentication Module**: Implement Argon2id password hashing, RS256 JWT generation, and opaque refresh tokens stored in MongoDB.
3. **RBAC & MFA**: Implement `require_roles` dependencies. Add TOTP MFA support.
4. **Security Middleware**: Add Rate limiting (in-memory/Mongo), CORS configuration (strict origin), and Security headers (CSP, HSTS).
5. **Model Security**: Add SHA-256 integrity checks for `.pkl` files before unpickling.

## Phase 3: Frontend Refactoring
1. **Store Migration**: Strip auth logic from `src/lib/store.ts`. It will now call the real backend APIs for login/signup/refresh.
2. **UI Updates**: Add MFA enrollment/verification flows in `AuthScreen.tsx`. Ensure dashboards fetch data from protected endpoints.

## Phase 4: Logging & Alerting
1. **Audit Logs**: Implement tamper-evident audit logging in MongoDB.
2. **Alert Engine**: Add background task to evaluate 5 security rules and generate alerts.
3. **Admin UI**: Add a Security tab in `AdminDashboard.tsx` to view logs and alerts.

## Phase 5: DevSecOps Pipeline & Testing
1. **GitHub Actions**: Create `.github/workflows/security-pipeline.yml` (SAST, SCA, Secret Scanning, Container Scan, DAST).
2. **Test Scripts**: Write pytest cases in `tests/security/` and curl demos in `scripts/demo/` for SQLi, RBAC, Rate limits, XSS, Tokens, etc.
3. **Documentation**: Write `SECURITY_REPORT.md` and `COMPLIANCE_MATRIX.md`.
