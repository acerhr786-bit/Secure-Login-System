# SecureAuth — Production-Grade Secure Authentication Web Application & Cybersecurity Lab

An enterprise-ready, defensive-by-design **Secure Login and Session Management System** built for modern web standards and beginner-to-intermediate cybersecurity students.

---

## 1. System Architecture & Threat Model Overview

```
                      ┌───────────────────────────────────────┐
                      │             Web Browser               │
                      └──────────────────┬────────────────────┘
                                         │
                   HTTPS / SameSite=Strict HttpOnly Session Cookie
                   Double Submit / WTForms CSRF Header
                                         │
                                         ▼
                      ┌───────────────────────────────────────┐
                      │        Reverse Proxy / Express        │
                      │  • Security Headers (OWASP Helmet)    │
                      │  • Rate Limiting (Sliding Window)     │
                      │  • Input Validation & Sanitization    │
                      └──────────────────┬────────────────────┘
                                         │
                                         ▼
                      ┌───────────────────────────────────────┐
                      │          Authentication Core          │
                      │  • Bcrypt Hashing (Cost Factor 12)    │
                      │  • RFC 6238 TOTP (Google Auth 2FA)    │
                      │  • Timing-Safe Comparison             │
                      │  • Single-Use Password Reset Tokens   │
                      └──────────────────┬────────────────────┘
                                         │
                            Parameterized Prepared Statements
                                         │
                                         ▼
                      ┌───────────────────────────────────────┐
                      │           SQLite Database             │
                      │  • users (hashed passwords, secrets)  │
                      │  • sessions (256-bit crypto tokens)   │
                      │  • password_reset_tokens (SHA-256)    │
                      │  • security_logs (audit telemetry)    │
                      └───────────────────────────────────────┘
```

---

## 2. Key Security Mechanisms & Defenses

| Security Threat | Attack Vector | Implemented Defense Mechanism |
| :--- | :--- | :--- |
| **SQL Injection (SQLi)** | Malicious SQL syntax in inputs (`' OR '1'='1`) | **100% Parameterized Queries / SQLAlchemy ORM**. User inputs are strictly treated as data literals, never executable query tokens. |
| **Credential Theft** | Database breach leaking plain-text passwords | **Bcrypt Password Hashing (Cost Factor 12)** with cryptographically unique salts. Passwords are never stored in plain text. |
| **Cross-Site Request Forgery (CSRF)** | Malicious third-party site submitting requests | **Double Submit Cookie & WTForms CSRF Tokens**. Every state-changing request (`POST`, `PUT`, `DELETE`) requires a verified HMAC token. |
| **Brute Force & Credential Stuffing** | Automated rapid-fire dictionary attacks | **Sliding Window Rate Limiter**. Automatically throttles requests and temporarily locks accounts after 5 failed attempts per IP/user. |
| **User Enumeration** | Timing differences or varying error messages | **Generic Error Messaging** (`"Invalid email or password"`) and **Constant-Time Verification** via dummy hash execution when users do not exist. |
| **Session Hijacking** | XSS stealing cookies, man-in-the-middle sniffing | **HttpOnly, SameSite=Strict / Lax, Secure Cookies** with cryptographically secure 256-bit entropy tokens and server-side invalidation. |
| **Account Takeover** | Stolen primary password | **Two-Factor Authentication (2FA)** using RFC 6238 TOTP (compatible with Google Authenticator, Authy, etc.). |
| **Insecure Password Resets** | Replay attacks, predictable tokens | **Single-Use, Time-Limited (15-min) Cryptographic Tokens** stored as SHA-256 hashes in the database. |

---

## 3. Project Structure

```
├── flask_app/                     # Complete Python & Flask implementation
│   ├── app.py                     # Flask application factory, routes & security middleware
│   ├── models.py                  # SQLAlchemy User & SecurityLog models
│   ├── forms.py                   # Flask-WTF forms with complexity validators
│   ├── templates/                 # Secure Jinja2 HTML templates
│   │   ├── base.html              # Base layout with CSP & navigation
│   │   ├── login.html             # Login form with password toggle
│   │   ├── register.html          # Registration form with strength meter
│   │   ├── dashboard.html         # Authenticated dashboard & audit logs
│   │   ├── two_factor.html        # 2FA challenge during login
│   │   ├── two_factor_setup.html  # 2FA QR code & activation
│   │   ├── reset_request.html     # Password reset request form
│   │   ├── reset_token.html       # Set new password form
│   │   └── change_password.html   # Authenticated password update form
│   └── tests/
│       └── test_auth.py           # Automated security test suite
├── server/                        # Node.js / Express security engine
│   ├── db.ts                      # Parameterized SQLite initialization
│   └── security.ts                # Bcrypt, TOTP, CSRF, and rate limiting logic
├── server.ts                      # Full-stack server with Vite middlewares
├── src/                           # Modern interactive React frontend & Security Lab
│   ├── App.tsx                    # Main auth UI & interactive security inspector
│   └── main.tsx                   # React entry point
├── requirements.txt               # Python package dependencies
├── package.json                   # Node.js dependencies & scripts
└── README.md                      # Comprehensive security documentation
```

---

## 4. How to Run Locally (Python & Flask)

### Prerequisites
- Python 3.10 or higher
- `pip` package manager

### Step-by-Step Instructions

1. **Clone or navigate to the project directory:**
   ```bash
   cd secure-login-system
   ```

2. **Create and activate a virtual environment:**
   ```bash
   # Linux / macOS:
   python3 -m venv venv
   source venv/bin/activate

   # Windows:
   python -m venv venv
   venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize database & start the Flask server:**
   ```bash
   export FLASK_APP=flask_app.app
   export FLASK_ENV=development
   flask run --port=5000
   ```
   *Windows Command Prompt:*
   ```cmd
   set FLASK_APP=flask_app.app
   flask run --port=5000
   ```

5. **Access the application:**
   Open your browser and navigate to `http://127.0.0.1:5000`.

---

## 5. Running the Automated Security Tests

Run the security test suite to verify protection against SQL injection, CSRF enforcement, password hashing, and access control:

```bash
# Using pytest:
pytest flask_app/tests/test_auth.py -v

# Or using standard unittest:
python3 -m unittest flask_app/tests/test_auth.py
```

All 7 security test suites verify:
- Bcrypt hash format (`$2b$12$...`) and plain-text non-storage
- Parameterized query immunity against injection payloads (`' OR '1'='1`)
- Password complexity enforcement (8+ chars, uppercase, lowercase, number, symbol)
- Generic error messages preventing user enumeration
- Unauthenticated access control redirects
- RFC 6238 TOTP 2FA code generation and verification
- Rejection of state-changing requests lacking CSRF tokens

---

## 6. Interactive Web Cybersecurity Lab (Node & React)

This project also includes an active full-stack interactive dashboard running live on port 3000. It includes:
- **Interactive SQL Injection Defense Probe**: Test payloads in real time and inspect SQLite's parameterized execution.
- **Bcrypt Work Factor & Timing Inspector**: Visualize algorithm parameters, cost rounds ($2^{12}$ iterations), and cryptographic salts.
- **Session Manager**: View active IP addresses and user agents, revoke other sessions, or terminate credentials.
- **Two-Factor Authentication Setup**: Live QR code generator for Google Authenticator / Authy.
- **Password Reset Simulation**: Request tokens and observe single-use time-limited invalidation.
- **Live Security Audit Log**: Real-time telemetry tracking successful logins, failed attempts, and security state modifications.
