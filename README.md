# CipherShield — CodeAlpha Cloud Computing Internship (Task 2)

**Project: Detecting Data Leaks Using SQL Injection**

CipherShield is a Flask and MySQL web application developed to demonstrate practical web application security concepts. It focuses on SQL injection prevention, secure authentication, sensitive profile data encryption, CSRF protection, login throttling, and security event logging.

The project is designed for local development and testing, with documentation for a potential AWS EC2 and RDS deployment.

## 1. Task 2 Requirement Mapping

| Requirement | Implementation |
|---|---|
| SQL Injection Prevention | Parameterized MySQL queries |
| AES-256 Encryption | AES-256-GCM encryption for supported sensitive profile fields |
| SQL Injection Testing | Controlled demonstration using parameterized queries |
| Multiple Layers of Security | Authentication, query parameterization, encryption, CSRF protection, and security logging |
| Cloud Deployment Preparation | AWS EC2 and RDS deployment documentation |

**Important:** Passwords are hashed using Werkzeug's password-hashing functions. They are not stored as plaintext and are not reversibly encrypted. AES-256-GCM is used for sensitive profile fields that require reversible encryption.

## 2. Features

- Responsive cybersecurity-themed interface
- User registration and authentication
- Secure password hashing
- Parameterized SQL queries
- AES-256-GCM encryption for supported sensitive profile fields
- CSRF protection for applicable form submissions
- Temporary login throttling after repeated failed attempts
- Security event logging
- Security Center for reviewing application events
- Controlled SQL Injection demonstration
- MySQL database integration
- Environment-based configuration and secrets
- Configurable application host and port
- AWS EC2 and RDS deployment guide

Security features should be considered verified only after the corresponding tests have passed.

## 3. Technology Stack

- **Backend:** Python, Flask
- **Database:** MySQL
- **Database connector:** MySQL Connector/Python
- **Authentication:** Werkzeug password hashing
- **Encryption:** Python cryptography library, AES-GCM
- **Configuration:** python-dotenv
- **Frontend:** HTML, CSS, Jinja templates
- **Deployment documentation:** AWS EC2 and Amazon RDS

## 4. Project Structure

```text
CipherShield/
├── app.py
├── database.py
├── schema.sql
├── test_db.py
├── requirements.txt
├── requirements-dev.txt
├── requirements-dev-lock.txt
├── README.md
├── SONARCLOUD_FIX_NOTES.md
├── static/
│   ├── app.js
│   ├── favicon.svg
│   └── style.css
├── templates/
│   ├── base.html
│   ├── dashboard.html
│   ├── error.html
│   ├── index.html
│   ├── login.html
│   ├── privacy.html
│   ├── profile.html
│   ├── register.html
│   ├── security_center.html
│   ├── security_demo.html
│   └── terms.html
└── tests/
    ├── test_app_security.py
    ├── test_database_config.py
    └── test_login_throttle.py
```

## 5. Local Setup

### Prerequisites

- Python 3.10 or a compatible supported version
- MySQL Server
- MySQL Workbench or another MySQL client
- Git (optional for version control)

### Step 1: Open the project directory

Open the extracted project folder in VS Code and open its integrated terminal.

### Step 2: Create a virtual environment

Run these commands if the project does not already have a working virtual environment:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

If the virtual environment is already active, do not create it again.

### Step 3: Install dependencies

```powershell
python -m pip install -r requirements.txt
```

### Step 4: Create the database

Open MySQL Workbench and execute the contents of `schema.sql`.

Alternatively, if your MySQL client supports the `SOURCE` command and you have opened the appropriate MySQL session, run:

```sql
SOURCE C:/path/to/project/schema.sql;
```

Replace the example path with the actual location of your file.

### Step 5: Configure environment variables

Copy `.env.example` to `.env` and fill in the values required by the application.

Configure your own:

- MySQL host, database name, username, and password
- A unique, strong Flask secret key
- A valid AES-256 key
- Environment and cookie settings appropriate for local development or deployment

Generate an AES key using:

```powershell
python generate_key.py
```

Generate a Flask secret key using:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Use the generated values in `.env` under the variable names expected by the application.

**Never commit or share `.env` or disclose your secret keys.** The ZIP and repository should contain placeholders in `.env.example`, not real credentials.

### Step 6: Test the database connection

```powershell
python test_db.py
```

Expected output on a successful connection:

```text
Database connection: SUCCESS
Database: codealpha_security
```

The exact output depends on the implementation of `test_db.py`.

### Step 7: Run the application

```powershell
python app.py
```

Open the local address shown in the terminal, typically:

http://127.0.0.1:5000

The local development address is not a publicly accessible cloud deployment.

## 6. Demonstrating the Project

1. Open the registration page and create a test account.
2. Log in using the test account.
3. Open the dashboard.
4. Open the protected profile page and enter test data in supported sensitive fields.
5. Inspect the corresponding database record to verify password hashing and profile-field encryption.
6. Open the Security Lab.
7. Submit a harmless SQL injection test string, such as `' OR '1'='1`.
8. Verify that the application uses parameterized queries and does not grant unauthorized access.
9. Open the Security Center and inspect the recorded authentication and profile events.
10. Test logout and verify that protected pages cannot be accessed without authentication.

Use dummy accounts and test data during demonstrations.

## 7. Testing and Verification

### Automated Test Suite

The project includes automated security and database tests using Python's `unittest` and `pytest` frameworks.

Run the complete test suite:

```powershell
python -m pytest -v
```

Run tests using the same command configured in GitHub Actions:

```powershell
python -m unittest discover -s tests -v
```

### Code Coverage

Generate a code coverage report:

```powershell
python -m pytest --cov=app --cov=database --cov-report=term-missing
```

Latest verified coverage:

| Module | Coverage |
|---|---:|
| app.py | 95% |
| database.py | 100% |
| **Overall** | **96%** |

### Static and Dependency Security Checks

Run Python compilation:

```powershell
python -m compileall -q app.py database.py tests
```

Audit production dependencies:

```powershell
python -m pip_audit -r requirements.txt
```

Check Git whitespace errors:

```powershell
git diff --check
```

### Hash-Verified Dependency Installation

Install production dependencies:

```powershell
python -m pip install --only-binary=:all: --require-hashes -r requirements-lock.txt
```

Install development dependencies:

```powershell
python -m pip install --only-binary=:all: --require-hashes -r requirements-dev-lock.txt
```

### Verified Test Execution Record

The following results have been verified in the local development environment:

| Check | Verified Result |
|---|---|
| Automated tests | 62 passed, 0 failed |
| Python 3.12.10 compatibility | 62 tests passed |
| Python 3.13.17 compatibility | 62 tests passed |
| Overall code coverage | 96% |
| Database module coverage | 100% |
| Python compilation | Passed |
| Dependency vulnerability audit | No known vulnerabilities found |
| Hash-verified dependency installation | Passed |
| Git whitespace check | No whitespace errors |
| SonarCloud analysis / Quality Gate | Pending fresh scan |

### Continuous Integration

GitHub Actions is configured to run on pushes and pull requests targeting the `main` branch.

The workflow:
- Uses Python 3.12.
- Installs dependencies using hash-verified lock files.
- Runs the complete test suite using `unittest discover`.

A passing local test suite does not automatically confirm that the remote GitHub Actions workflow or SonarCloud Quality Gate has passed. Verify their actual results after pushing the changes.

A passing unit test suite also does not replace end-to-end testing, database testing, or an independent security review.

## 8. Security Considerations

### SQL Injection

Use parameterized SQL statements for user-controlled values. Avoid building SQL queries by concatenating untrusted input.

The demonstration lab should use safe, parameterized queries rather than execute arbitrary SQL supplied by the user.

### Password Security

Passwords should be stored using a suitable password-hashing algorithm with appropriate work factors. Password hashes should not be treated as reversible encryption.

### Sensitive Data Encryption

AES-256-GCM provides authenticated encryption when used correctly with a unique nonce for each encryption under a given key. Keys must be kept separate from encrypted database data.

Changing the AES key without a planned migration or re-encryption process can make existing encrypted values unreadable.

### CSRF and Session Security

Use CSRF tokens for applicable state-changing requests. Configure secure cookie attributes and appropriate session settings for the deployment environment.

### Security Headers and HTTPS

Verify security headers against actual HTTP responses. Configure Content Security Policy and other applicable headers according to the application's resources and requirements.

HSTS should be enabled only for an HTTPS deployment with an appropriate domain and configuration.

### Login Throttling

The current login throttle uses in-memory state. It is intended for a local, single-process demonstration and resets when the application restarts.

In-memory throttling is not sufficient for a multi-worker or multi-instance production deployment. A production system should use a shared persistent rate-limiting store, consider per-IP limits, and apply monitoring and alerting.

### Secrets Management

- Do not commit `.env` or production credentials.
- Use unique, strong secret values.
- Do not expose database credentials, encryption keys, or sensitive information in logs.
- Use least-privilege database permissions.

## 9. AWS Deployment Preparation

See `docs/AWS_EC2_RDS_DEPLOYMENT.md` for the documented EC2 and RDS deployment procedure.

For a public deployment:

- Set `APP_ENV=production`.
- Configure strong, unique Flask and AES keys.
- Use HTTPS through an appropriately configured reverse proxy or load balancer.
- Set `COOKIE_SECURE=1` when HTTPS is enabled and the application supports this setting.
- Restrict the RDS security group so that database access is permitted only from the application server's security group.
- Do not expose MySQL port 3306 publicly.
- Disable development debugging and configure production-grade logging.
- Use an appropriate production WSGI server and review multi-worker behavior.
- Configure backups, monitoring, patching, and key management.

**Deployment status:** The presence of deployment documentation does not mean that the application has already been deployed to AWS. Describe the project as locally tested and cloud-deployment-ready only to the extent supported by actual verification.

## 10. Current Limitations

- Login throttling is in-memory and is not suitable for multi-instance production use.
- Local testing does not prove security under internet-facing conditions.
- The SQL Injection lab demonstrates safe query handling; it is not a substitute for a comprehensive penetration test.
- AWS deployment remains incomplete until the application is actually deployed and verified in the target environment.

## 11. Future Improvements

- Shared rate limiting with Redis
- Per-IP and account-based abuse protection
- Automated integration and security tests
- Centralized monitoring and alerting
- Production secret management and encryption-key rotation
- HTTPS deployment and hardened cloud infrastructure
- Dependency vulnerability scanning and periodic security reviews

## 12. Disclaimer

CipherShield is an educational security project intended to demonstrate secure web application development and SQL Injection prevention.

No application can be guaranteed to be 100% secure. Security depends on the implementation, configuration, deployment environment, dependencies, and ongoing maintenance.

---

**Project:** CipherShield — Detecting Data Leaks Using SQL Injection
**Internship:** CodeAlpha Cloud Computing — Task 2
