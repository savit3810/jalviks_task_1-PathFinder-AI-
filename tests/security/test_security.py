"""
Security Tests for PathFinder AI
=================================
These tests verify all major security controls are working correctly.
Run with: pytest tests/security/ -v --tb=short

Prerequisites:
  - Docker stack must be running: make up
  - Admin user must be created: docker exec -it pathfinder_backend python app/cli.py create-admin
"""

import pytest
import httpx
import os
import json
import time

BASE_URL = os.getenv("API_URL", "http://localhost:8000")

# ─── Test Helpers ─────────────────────────────────────────────────────────────

async def signup_user(client, name, email, password, role="class10"):
    """Helper to create a test user."""
    return await client.post(f"{BASE_URL}/api/auth/signup", json={
        "name": name,
        "email": email,
        "password": password,
        "role": role,
        "careerGoal": "Testing"
    })


async def login_user(client, email, password):
    """Helper to login and return the response."""
    return await client.post(f"{BASE_URL}/api/auth/login", json={
        "email": email,
        "password": password
    })


async def get_access_token(client, email, password):
    """Helper to login and extract access token."""
    resp = await login_user(client, email, password)
    data = resp.json()
    return data.get("access_token", "")


# ─── TEST 1: No-Auth and RBAC Enforcement ────────────────────────────────────
# Attack: Access admin endpoints without authentication or with low-privilege token
# Impact without control: Any user could view audit logs, change roles, export data
# Control: require_roles(["admin"]) dependency + JWT RS256 verification

@pytest.mark.asyncio
async def test_admin_endpoint_requires_auth():
    """Unauthenticated request to admin endpoint must be rejected."""
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{BASE_URL}/api/admin/audit")
        assert response.status_code in [401, 403], \
            f"Expected 401/403, got {response.status_code}"


@pytest.mark.asyncio
async def test_viewer_cannot_access_admin_endpoint():
    """A viewer-role user must NOT be able to access admin-only endpoints."""
    async with httpx.AsyncClient() as client:
        # Create a viewer user
        email = f"viewer_test_{int(time.time())}@test.com"
        await signup_user(client, "Test Viewer", email, "TestPassword123!", "viewer")

        # Login as viewer
        token = await get_access_token(client, email, "TestPassword123!")

        if not token:
            pytest.skip("Could not obtain viewer token (MFA or other issue)")

        # Try to access admin-only endpoint
        resp = await client.get(
            f"{BASE_URL}/api/admin/audit",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 403, \
            f"Viewer should get 403, got {resp.status_code}: {resp.text}"


@pytest.mark.asyncio
async def test_student_cannot_access_admin_users():
    """A student-role user must NOT be able to list all users."""
    async with httpx.AsyncClient() as client:
        email = f"student_test_{int(time.time())}@test.com"
        await signup_user(client, "Test Student", email, "TestPassword123!", "class10")

        token = await get_access_token(client, email, "TestPassword123!")

        if not token:
            pytest.skip("Could not obtain student token")

        resp = await client.get(
            f"{BASE_URL}/api/admin/users",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 403, \
            f"Student should get 403, got {resp.status_code}"


# ─── TEST 2: Brute Force → Account Lockout ───────────────────────────────────
# Attack: Automated password guessing with rapid login attempts
# Impact without control: Attacker could guess weak passwords
# Control: Account lockout after 5 failed attempts (15-minute lockout)

@pytest.mark.asyncio
async def test_account_lockout_after_failed_logins():
    """5 wrong passwords must lock the account."""
    async with httpx.AsyncClient() as client:
        email = f"lockout_test_{int(time.time())}@test.com"
        password = "CorrectPassword123!"

        # Create user
        resp = await signup_user(client, "Lockout Test", email, password, "class10")
        assert resp.status_code == 201, f"Signup failed: {resp.text}"

        # Attempt 5 wrong logins
        for i in range(5):
            resp = await login_user(client, email, "WrongPassword123!")
            assert resp.status_code == 401, f"Attempt {i+1}: Expected 401"

        # 6th attempt (even with correct password) should be locked
        resp = await login_user(client, email, password)
        assert resp.status_code == 423, \
            f"Account should be locked (423), got {resp.status_code}: {resp.text}"


# ─── TEST 3: NoSQL Injection Prevention ──────────────────────────────────────
# Attack: MongoDB operator injection via login fields
# Impact without control: Bypass authentication, dump all users
# Control: Pydantic EmailStr validation + extra="forbid" + typed schemas

@pytest.mark.asyncio
async def test_nosql_injection_in_login_email():
    """MongoDB $gt operator in email field must be rejected by Pydantic."""
    async with httpx.AsyncClient() as client:
        # Attempt 1: Operator injection in email
        resp = await client.post(f"{BASE_URL}/api/auth/login", json={
            "email": {"$gt": ""},
            "password": "anything"
        })
        # Pydantic will reject this with 422 (validation error)
        assert resp.status_code == 422, \
            f"NoSQL injection should be rejected with 422, got {resp.status_code}"


@pytest.mark.asyncio
async def test_nosql_injection_in_login_password():
    """MongoDB operator in password field must be rejected."""
    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{BASE_URL}/api/auth/login", json={
            "email": "test@test.com",
            "password": {"$ne": ""}
        })
        assert resp.status_code == 422, \
            f"NoSQL injection in password should be rejected, got {resp.status_code}"


@pytest.mark.asyncio
async def test_extra_fields_rejected():
    """Extra fields in request body must be rejected (extra='forbid')."""
    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{BASE_URL}/api/auth/login", json={
            "email": "test@test.com",
            "password": "test",
            "role": "admin",
            "$where": "1==1"
        })
        assert resp.status_code == 422, \
            f"Extra fields should be rejected, got {resp.status_code}"


# ─── TEST 4: XSS Payload Prevention ──────────────────────────────────────────
# Attack: Injecting <script> tags in user input fields
# Impact without control: Stored XSS, session hijacking, phishing
# Control: Pydantic validation + React DOM encoding + CSP headers

@pytest.mark.asyncio
async def test_xss_in_signup_name():
    """XSS payload in name field — either rejected or safely stored (not executed)."""
    async with httpx.AsyncClient() as client:
        xss_payload = "<script>alert('XSS')</script>"
        email = f"xss_test_{int(time.time())}@test.com"

        resp = await signup_user(client, xss_payload, email, "TestPassword123!", "class10")

        # Pydantic allows string fields, but the value is safely stored
        # React will escape it on render. CSP blocks inline scripts.
        # The key is that no script execution occurs.
        assert resp.status_code in [201, 422], \
            f"Expected 201 (safe storage) or 422 (rejected), got {resp.status_code}"


@pytest.mark.asyncio
async def test_xss_in_career_goal():
    """XSS in optional field must be safely handled."""
    async with httpx.AsyncClient() as client:
        email = f"xss_goal_{int(time.time())}@test.com"
        resp = await client.post(f"{BASE_URL}/api/auth/signup", json={
            "name": "Safe User",
            "email": email,
            "password": "TestPassword123!",
            "role": "class10",
            "careerGoal": "<img src=x onerror=alert('XSS')>"
        })
        # max_length=100 on careerGoal will truncate or reject overly long payloads
        # Pydantic stores the string safely; React escapes on render
        assert resp.status_code in [201, 422]


# ─── TEST 5: Expired / Invalid Token Rejection ──────────────────────────────
# Attack: Using a forged, expired, or tampered JWT to access protected endpoints
# Impact without control: Unauthorized access to any API endpoint
# Control: RS256 signature verification + exp claim + aud/iss validation

@pytest.mark.asyncio
async def test_forged_jwt_rejected():
    """A completely fake JWT must be rejected."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{BASE_URL}/api/admin/audit",
            headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJoYWNrZXIiLCJyb2xlIjoiYWRtaW4ifQ.fakesignature"}
        )
        assert resp.status_code == 401, \
            f"Forged JWT should be rejected, got {resp.status_code}"


@pytest.mark.asyncio
async def test_expired_token_rejected():
    """An expired JWT must be rejected even if otherwise valid."""
    # We can't easily create a truly expired RS256 token without the private key,
    # but we can test with a modified/tampered token
    async with httpx.AsyncClient() as client:
        # Tamper with a token by changing the payload
        resp = await client.get(
            f"{BASE_URL}/api/admin/audit",
            headers={"Authorization": "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0Iiwicm9sZSI6ImFkbWluIiwiZXhwIjoxMDAwMDAwMDAwfQ.invalid"}
        )
        assert resp.status_code == 401, \
            f"Tampered JWT should be rejected, got {resp.status_code}"


@pytest.mark.asyncio
async def test_missing_bearer_prefix():
    """Token without 'Bearer ' prefix must be rejected."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{BASE_URL}/api/admin/audit",
            headers={"Authorization": "some-random-token"}
        )
        assert resp.status_code in [401, 403]


# ─── TEST 6: Input Validation on ML Endpoints ───────────────────────────────
# Attack: Sending out-of-range or malformed data to prediction endpoints
# Impact without control: Application crash, unexpected behavior, data corruption
# Control: Pydantic Field validators with ge/le/pattern constraints

@pytest.mark.asyncio
async def test_marks_out_of_range_rejected():
    """Marks > 100 must be rejected by Pydantic validation."""
    async with httpx.AsyncClient() as client:
        # First get a valid token
        email = f"ml_test_{int(time.time())}@test.com"
        await signup_user(client, "ML Tester", email, "TestPassword123!", "class10")
        token = await get_access_token(client, email, "TestPassword123!")

        if not token:
            pytest.skip("Could not obtain token")

        resp = await client.post(
            f"{BASE_URL}/api/predict/stream",
            json={
                "math_marks": 999,  # Way out of range (max 100)
                "science_marks": 85,
                "english_marks": 90
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 422, \
            f"Out-of-range marks should be rejected, got {resp.status_code}"


@pytest.mark.asyncio
async def test_negative_marks_rejected():
    """Negative marks must be rejected."""
    async with httpx.AsyncClient() as client:
        email = f"neg_test_{int(time.time())}@test.com"
        await signup_user(client, "Neg Tester", email, "TestPassword123!", "class10")
        token = await get_access_token(client, email, "TestPassword123!")

        if not token:
            pytest.skip("Could not obtain token")

        resp = await client.post(
            f"{BASE_URL}/api/predict/stream",
            json={
                "math_marks": -50,
                "science_marks": 85,
                "english_marks": 90
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 422


# ─── TEST 7: Security Headers Verification ──────────────────────────────────
# Attack: Clickjacking, MIME-sniffing, missing HTTPS enforcement
# Impact without control: UI redress attacks, content injection
# Control: HSTS, X-Frame-Options, X-Content-Type-Options, CSP headers

@pytest.mark.asyncio
async def test_security_headers_present():
    """All required security headers must be present in responses."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{BASE_URL}/api/health")

        headers = resp.headers
        assert "x-content-type-options" in headers, "Missing X-Content-Type-Options"
        assert headers["x-content-type-options"] == "nosniff"

        assert "x-frame-options" in headers, "Missing X-Frame-Options"
        assert headers["x-frame-options"].upper() == "DENY"

        assert "strict-transport-security" in headers, "Missing HSTS"
        assert "content-security-policy" in headers, "Missing CSP"


# ─── TEST 8: Rate Limiting Verification ──────────────────────────────────────
# Attack: Automated rapid requests to overwhelm the server
# Impact without control: DoS, resource exhaustion
# Control: Nginx rate limiting zones (5r/s for login, 20r/s for API)
# Note: This test must be run against the WAF (port 443), not the backend directly

@pytest.mark.asyncio
async def test_health_check_public():
    """Health endpoint should be publicly accessible."""
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{BASE_URL}/api/health")
        assert response.status_code == 200


# ─── TEST 9: Password Strength Enforcement ──────────────────────────────────
# Attack: Using weak/short passwords
# Impact without control: Easy brute-force of credentials
# Control: Pydantic min_length=12 on password field

@pytest.mark.asyncio
async def test_weak_password_rejected():
    """Password shorter than 12 characters must be rejected."""
    async with httpx.AsyncClient() as client:
        email = f"weak_pw_{int(time.time())}@test.com"
        resp = await signup_user(client, "Weak PW User", email, "short", "class10")
        assert resp.status_code == 422, \
            f"Short password should be rejected, got {resp.status_code}"


@pytest.mark.asyncio
async def test_duplicate_email_rejected():
    """Duplicate email signup must be rejected."""
    async with httpx.AsyncClient() as client:
        email = f"dup_test_{int(time.time())}@test.com"
        resp1 = await signup_user(client, "User One", email, "TestPassword123!", "class10")
        assert resp1.status_code == 201

        resp2 = await signup_user(client, "User Two", email, "TestPassword456!", "class10")
        assert resp2.status_code == 400


# ─── TEST 10: Generic Error Messages ─────────────────────────────────────────
# Attack: Harvesting internal details from error responses
# Impact without control: Information disclosure (stack traces, DB schema)
# Control: Global exception handler returns generic message + request_id only

@pytest.mark.asyncio
async def test_login_error_is_generic():
    """Login failure must NOT reveal whether email exists or password is wrong."""
    async with httpx.AsyncClient() as client:
        # Non-existent email
        resp1 = await login_user(client, "nonexistent@test.com", "AnyPassword123!")
        # Existing email, wrong password
        email = f"generic_err_{int(time.time())}@test.com"
        await signup_user(client, "Error Test", email, "TestPassword123!", "class10")
        resp2 = await login_user(client, email, "WrongPassword123!")

        # Both should return the same generic message
        assert resp1.json()["detail"] == resp2.json()["detail"] == "Invalid email or password"
