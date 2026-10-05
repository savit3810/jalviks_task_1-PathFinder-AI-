# Security Testing Evidence

This document provides detailed evidence for each security test performed against the PathFinder AI application. Each test follows the format required by the assessment rubric.

---

## Test 1: RBAC Enforcement — Low-Privilege User Cannot Access Admin Functionality

### Attack Scenario
A user with `viewer` role obtains a valid JWT and directly calls `GET /api/admin/audit` to access the security audit logs, which should be restricted to administrators only.

### What Could Happen Without the Security Control
Without server-side role checks, any authenticated user could:
- View all security audit logs (revealing other users' login patterns, IPs, and activity)
- List all users in the system
- Export sensitive data
- Change other users' roles
- Modify system configuration

### Security Control Implemented
The `require_roles(["admin"])` dependency on every admin endpoint:
1. Extracts the JWT from the `Authorization` header
2. Verifies the RS256 signature using the server's public key
3. Validates `exp`, `iss`, and `aud` claims
4. Checks that `role` in the token payload is in the allowed list
5. Returns HTTP 403 and logs `FORBIDDEN_ACCESS` event if unauthorized

**Code location:** `api/core/dependencies.py` → `require_roles()` function

### How the Test Was Performed
```bash
# Step 1: Create a viewer user
curl -k -X POST https://localhost/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"name":"Test Viewer","email":"viewer@test.com","password":"ViewerPassword123!","role":"viewer"}'

# Step 2: Login as viewer to get JWT
curl -k -X POST https://localhost/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"viewer@test.com","password":"ViewerPassword123!"}'
# Response: {"access_token":"eyJhbG...","token_type":"bearer"}

# Step 3: Attempt to access admin-only endpoint with viewer token
curl -k -X GET https://localhost/api/admin/audit \
  -H "Authorization: Bearer eyJhbG..."
```

### Observed Result
```json
{
  "detail": "Not enough permissions"
}
```
**HTTP Status:** 403 Forbidden

The audit log in MongoDB shows:
```json
{
  "event_type": "FORBIDDEN_ACCESS",
  "severity": "medium",
  "outcome": "failure",
  "actor_user_id": "<viewer-user-id>",
  "actor_role": "viewer",
  "details": {"reason": "Role not allowed", "allowed": ["admin"]}
}
```

### Automated Test
```bash
pytest tests/security/test_security.py::test_viewer_cannot_access_admin_endpoint -v
pytest tests/security/test_security.py::test_student_cannot_access_admin_users -v
```

---

## Test 2: Brute-Force Login → Account Lockout

### Attack Scenario
An attacker attempts to guess a user's password by sending rapid automated login requests with different password guesses.

### What Could Happen Without the Security Control
Without account lockout:
- Attacker could try millions of password combinations
- Weak passwords could be compromised within minutes
- No indication that an attack is occurring
- Credential stuffing attacks would succeed against reused passwords

### Security Control Implemented
- After 5 consecutive failed login attempts, `locked_until` is set to `now + 15 minutes`
- During lockout, even the correct password returns HTTP 423
- The `ACCOUNT_LOCKED` security event is logged (severity: high)
- The alert engine detects ≥5 failures in 5 minutes and creates a `rule_brute_force_account` alert
- Nginx rate limiting (5 req/sec on `/api/auth/login`) provides an additional layer

**Code location:** `api/routers/auth.py` → `/login` endpoint (lines 71-80)

### How the Test Was Performed
```bash
# Step 1: Create a test user
curl -k -X POST https://localhost/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"name":"Lockout Test","email":"lockout@test.com","password":"CorrectPassword123!","role":"class10"}'

# Step 2: Send 5 wrong password attempts
for i in {1..5}; do
  echo "Attempt $i:"
  curl -k -s -o /dev/null -w "%{http_code}" -X POST https://localhost/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"lockout@test.com","password":"WrongPassword'$i'!"}'
  echo ""
done

# Step 3: Try with correct password (should still be locked)
curl -k -X POST https://localhost/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"lockout@test.com","password":"CorrectPassword123!"}'
```

### Observed Result
```
Attempt 1: 401 (Invalid email or password)
Attempt 2: 401 (Invalid email or password)
Attempt 3: 401 (Invalid email or password)
Attempt 4: 401 (Invalid email or password)
Attempt 5: 401 (Invalid email or password) + ACCOUNT_LOCKED event logged
Attempt 6 (correct password): 423 ("Account is locked. Please try again later.")
```

The MongoDB `users` collection shows:
```json
{
  "email": "lockout@test.com",
  "failed_logins": 5,
  "locked_until": "2026-10-05T12:15:00Z"
}
```

### Automated Test
```bash
pytest tests/security/test_security.py::test_account_lockout_after_failed_logins -v
```

---

## Test 3: NoSQL Injection Prevention

### Attack Scenario
An attacker sends MongoDB query operators in the login request body to bypass authentication:
```json
{"email": {"$gt": ""}, "password": {"$ne": ""}}
```
This would match the first user whose email is "greater than" an empty string (i.e., any user) and whose password is "not equal to" an empty string (i.e., any password).

### What Could Happen Without the Security Control
Without input validation:
- Attacker bypasses authentication entirely
- Attacker gains access as the first user in the database (often an admin)
- All user data is exposed
- This is a classic MongoDB injection equivalent to SQL injection

### Security Control Implemented
- **Pydantic `EmailStr` type:** Validates that the `email` field is a valid email string — rejects objects like `{"$gt": ""}`
- **Pydantic `extra = "forbid"`:** Rejects any fields not defined in the schema — blocks `$where`, `$regex`, etc.
- **Motor typed queries:** All MongoDB queries use Python dictionaries with validated inputs — no string concatenation

**Code location:** `api/schemas/user.py` → `UserLogin` class

### How the Test Was Performed
```bash
# Attempt 1: Operator injection in email
curl -k -X POST https://localhost/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": {"$gt": ""}, "password": "anything"}'

# Attempt 2: Operator injection in password
curl -k -X POST https://localhost/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "test@test.com", "password": {"$ne": ""}}'

# Attempt 3: Extra MongoDB operators
curl -k -X POST https://localhost/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "test@test.com", "password": "test", "$where": "1==1"}'
```

### Observed Result
All three attempts return **HTTP 422 Unprocessable Entity**:
```json
{
  "detail": [
    {
      "type": "string_type",
      "loc": ["body", "email"],
      "msg": "Input should be a valid string",
      "input": {"$gt": ""}
    }
  ]
}
```
The injection payload **never reaches MongoDB** — Pydantic rejects it at the validation layer.

### Automated Test
```bash
pytest tests/security/test_security.py::test_nosql_injection_in_login_email -v
pytest tests/security/test_security.py::test_nosql_injection_in_login_password -v
pytest tests/security/test_security.py::test_extra_fields_rejected -v
```

---

## Test 4: XSS Payload Prevention

### Attack Scenario
An attacker registers an account with a malicious name:
```json
{"name": "<script>alert('XSS')</script>", "email": "xss@test.com", ...}
```
If this name is displayed on the admin dashboard without encoding, the script executes in the admin's browser, potentially stealing their session token.

### What Could Happen Without the Security Control
Without XSS prevention:
- Stored XSS executes whenever the payload is rendered
- Attacker steals admin's JWT token via `document.cookie` or `fetch()`
- Attacker gains full admin access
- Can lead to complete application compromise

### Security Control Implemented
**Three layers of defense:**
1. **React DOM escaping:** React automatically escapes all values in JSX — `<script>` becomes `&lt;script&gt;` in the HTML output
2. **Content-Security-Policy:** `script-src 'self'` prevents inline script execution even if encoding is bypassed
3. **WAF pattern blocking:** Nginx WAF blocks requests containing `<script>`, `javascript:`, `on*=` patterns in URL parameters

**Code locations:** 
- WAF: `nginx/waf.conf` (lines 64-74)
- CSP: `nginx/waf.conf` (line 42) + `api/app/main.py` (line 34)

### How the Test Was Performed
```bash
# Attempt 1: XSS in name field via API
curl -k -X POST https://localhost/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"name":"<script>alert(1)</script>","email":"xss@test.com","password":"TestPassword123!","role":"class10"}'

# Attempt 2: XSS in URL parameter (blocked by WAF)
curl -k "https://localhost/api/health?q=<script>alert(1)</script>"
```

### Observed Result
- **API attempt:** HTTP 201 — the string is stored in MongoDB as a literal string `<script>alert(1)</script>`. When rendered by React, it appears as plain text, not executable code.
- **URL attempt:** HTTP 403 — WAF blocks the request before it reaches the backend.
- **CSP verification:** Browser DevTools shows the Content-Security-Policy header preventing any inline scripts.

### Automated Test
```bash
pytest tests/security/test_security.py::test_xss_in_signup_name -v
pytest tests/security/test_security.py::test_xss_in_career_goal -v
```

---

## Test 5: Expired / Forged Token Rejection

### Attack Scenario
An attacker crafts a JWT with `"role": "admin"` and signs it with their own key (or uses HS256 with a guessed secret) to gain administrator access without valid credentials.

### What Could Happen Without the Security Control
Without proper JWT validation:
- Attacker creates tokens with any role, bypassing authentication entirely
- Expired tokens continue to grant access indefinitely
- Algorithm confusion attacks (HS256 vs RS256) could compromise the system

### Security Control Implemented
- **RS256 asymmetric signing:** Tokens can only be signed with the server's private key (never exposed)
- **Algorithm enforcement:** Only `RS256` algorithm accepted (prevents algorithm confusion)
- **Claim validation:** `iss` (pathfinder-api), `aud` (pathfinder-client), `exp`, `nbf`, `type` all verified
- **10-minute expiry:** Minimizes the window for stolen tokens
- **Audit logging:** Every `UNAUTHORIZED_ACCESS` attempt is logged with source IP

**Code location:** `api/core/dependencies.py` → `require_roles()` (lines 27-36)

### How the Test Was Performed
```bash
# Attempt 1: Completely forged HS256 JWT with admin role
curl -k -X GET https://localhost/api/admin/audit \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJoYWNrZXIiLCJyb2xlIjoiYWRtaW4ifQ.fakesig"

# Attempt 2: Tampered RS256 JWT (modified payload, broken signature)
curl -k -X GET https://localhost/api/admin/audit \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0Iiwicm9sZSI6ImFkbWluIiwiZXhwIjoxMH0.invalid"

# Attempt 3: Missing Bearer prefix
curl -k -X GET https://localhost/api/admin/audit \
  -H "Authorization: some-random-token"
```

### Observed Result
All three attempts return **HTTP 401 Unauthorized**:
```json
{"detail": "Invalid token"}
```

The audit log shows:
```json
{
  "event_type": "UNAUTHORIZED_ACCESS",
  "severity": "medium",
  "outcome": "failure",
  "details": {"reason": "Invalid token"},
  "source_ip": "172.18.0.1"
}
```

### Automated Test
```bash
pytest tests/security/test_security.py::test_forged_jwt_rejected -v
pytest tests/security/test_security.py::test_expired_token_rejected -v
pytest tests/security/test_security.py::test_missing_bearer_prefix -v
```

---

## Test 6: Security Scan — Vulnerability Detection and Remediation

### Attack Scenario
The CI/CD pipeline identifies a security vulnerability in a dependency or source code pattern before deployment.

### What Could Happen Without the Security Control
Without automated scanning:
- Known vulnerabilities in dependencies go undetected
- Hardcoded secrets get committed to the repository
- Insecure code patterns (eval, wildcard CORS, etc.) reach production
- Vulnerable container base images are deployed

### Security Control Implemented
Five scanning tools run in the GitHub Actions pipeline:
1. **Semgrep** — detects OWASP Top 10 patterns in source code
2. **pip-audit** — checks Python dependencies against vulnerability databases
3. **npm audit** — checks Node.js dependencies
4. **Gitleaks** — scans git history for secrets
5. **Trivy** — scans Docker images for OS and library CVEs

All configured to **block the build** on HIGH/CRITICAL findings.

### Evidence: Baseline Findings and Remediation

| Finding | Tool | Status |
|---------|------|--------|
| Hardcoded admin password in `store.ts` | Gitleaks / Manual Review | **Remediated** — removed; admin created via CLI |
| Wildcard CORS (`allow_origins=["*"]`) | Semgrep | **Remediated** — restricted to `https://localhost` |
| Unsafe `pickle.load()` | Semgrep / Bandit | **Remediated** — SHA-256 manifest verification added |
| Verbose error messages | Manual Review | **Remediated** — global exception handler added |

### How to Run
```bash
# Locally
make scan-sast
make scan-sca

# Full pipeline runs automatically on push to main
# See: .github/workflows/security-pipeline.yml
```

---

## Summary of All Tests

| # | Test | Control | Result |
|---|------|---------|--------|
| 1 | RBAC: Viewer → Admin endpoint | `require_roles(["admin"])` | ✅ 403 Forbidden |
| 2 | Brute-force → Account lockout | 5-attempt lockout (15 min) | ✅ 423 Locked |
| 3 | NoSQL injection in login | Pydantic EmailStr + extra="forbid" | ✅ 422 Rejected |
| 4 | XSS payload in signup | React DOM + CSP + WAF | ✅ Safely handled |
| 5 | Forged JWT token | RS256 + claim validation | ✅ 401 Rejected |
| 6 | Security scan remediation | SAST + SCA + Secrets + Containers | ✅ All findings fixed |
| 7 | Out-of-range ML input | Pydantic Field(ge/le) | ✅ 422 Rejected |
| 8 | Weak password | Pydantic min_length=12 | ✅ 422 Rejected |
| 9 | Generic error messages | Global exception handler | ✅ No info leakage |
| 10 | Security headers | Nginx + FastAPI middleware | ✅ All present |
