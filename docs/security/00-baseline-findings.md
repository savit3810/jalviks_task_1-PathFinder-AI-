# Baseline Security Findings

## Executive Summary
A comprehensive security assessment of the PathFinder AI repository was conducted. The application currently suffers from critical architectural and implementation flaws, including client-side authentication, missing authorization, lack of transport security enforcement, and unsafe deserialization practices.

## Detailed Findings

### 1. Client-Side Authentication & Hardcoded Credentials
- **File:** `src/lib/store.ts`
- **Vulnerability:** Authentication logic is implemented entirely within the frontend using `zustand` and `localStorage`.
- **Evidence:** Accounts and plaintext passwords are saved to `localStorage` under `pathfinder_accounts_v2`. Admin credentials (`ADMIN_EMAIL = 'savit.m.singh@slrtce.in'`, `ADMIN_PASSWORD = 'Savit@2006'`) are hardcoded in the source code.
- **Risk:** Critical. Anyone with access to the client machine can view passwords. Hardcoded credentials allow immediate administrative access to anyone reading the source code.

### 2. Missing Authentication and Authorization on Backend APIs
- **File:** `api/index.py`
- **Vulnerability:** None of the FastAPI endpoints enforce authentication or role-based access control.
- **Evidence:** Endpoints like `/predict/stream`, `/seniors/match`, etc., have no `Depends` or security checks.
- **Risk:** Critical. Anyone can access any backend functionality without logging in, leading to potential abuse and data exposure.

### 3. Misconfigured Cross-Origin Resource Sharing (CORS)
- **File:** `api/index.py`
- **Vulnerability:** The CORS policy is extremely permissive.
- **Evidence:** `allow_origins=["*"]` along with `allow_credentials=True` (though FastAPI restricts this combination in recent versions, the intent is insecure).
- **Risk:** High. Allows any origin to make cross-origin requests, exposing the API to CSRF and data theft.

### 4. Lack of Rate Limiting, Brute Force Protection, and MFA
- **Vulnerability:** The application lacks controls against automated attacks.
- **Evidence:** No logic exists in `src/lib/store.ts` or `api/index.py` to limit login attempts or enforce Multi-Factor Authentication.
- **Risk:** High. Vulnerable to credential stuffing, brute-force attacks, and DoS.

### 5. Unsafe Deserialization
- **File:** `api/index.py`
- **Vulnerability:** Machine learning models are loaded using the native Python `pickle` module.
- **Evidence:** `pickle.load(f)` is used for files like `salary_model.pkl`.
- **Risk:** High. If an attacker can replace the `.pkl` files (e.g., via a compromised CI/CD pipeline or file upload), they can execute arbitrary code upon model loading.

### 6. Verbose Error Handling
- **File:** `api/index.py`, `api/db.py`
- **Vulnerability:** Unhandled exceptions and verbose errors are returned or printed.
- **Evidence:** Use of raw `print` statements for MongoDB errors and lack of global exception handlers masking stack traces.
- **Risk:** Medium. Exposes internal application state, database paths, and structure to attackers.

### 7. Sensitive and Junk Artefacts in Repository
- **Vulnerability:** Multiple unnecessary or sensitive files are committed.
- **Evidence:** `dev_output.txt`, `api/import_test.txt`, `push_to_github.bat`, `vite.config.ts.timestamp-*.mjs`, duplicated `train_model.py`/`train_models.py`, and `.pkl` files are present in the repository.
- **Risk:** Low-Medium. Clutters the repository and may inadvertently leak internal development paths or configurations.

### 8. Legacy Code and Documentation Exposing Credentials
- **Vulnerability:** `README.md` and the legacy `frontend/` directory may contain or reference credentials.
- **Risk:** Medium.

## Remediation Plan
These vulnerabilities will be systematically addressed according to the Implementation Plan.
