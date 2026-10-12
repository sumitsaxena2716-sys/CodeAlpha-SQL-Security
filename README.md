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
CodeAlpha_SQL_Security_Task2/
├── app.py
├── database.py
├── schema.sql
├── requirements.txt
├── .env.example
├── .gitignore
├── generate_key.py
├── test_db.py
├── README.md
├── docs/
│   ├── CODEALPHA_TASK_MAPPING.md
│   ├── AWS_EC2_RDS_DEPLOYMENT.md
│   └── TASK_REPORT_TEMPLATE.md
├── tests/
│   └── test_login_throttle.py
├── static/
│   └── style.css
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── profile.html
│   ├── security_demo.html
│   ├── security_center.html
│   └── error.html
└── logs/
```

*Note: This is the documented structure. Confirm that each listed file and directory exists in your final project folder.*

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

The following checks should be performed before submission.

| Test | Expected result |
|---|---|
| Database connection | Application connects to the configured database |
| Registration | Valid test account is created |
| Password storage | Password is stored as a hash, not plaintext |
| Valid login | Correct credentials allow access |
| Invalid login | Incorrect credentials are rejected |
| Login throttling | Repeated failures trigger the configured temporary lockout |
| Lockout expiry | Login becomes available after the configured duration |
| SQL injection test | Test input does not bypass authentication or expose unauthorized records |
| Profile encryption | Supported sensitive fields are stored as ciphertext |
| Profile decryption | Authorized application flow retrieves the correct original value |
| CSRF protection | Applicable state-changing requests without valid CSRF protection are rejected |
| Security event logging | Relevant successful and failed events are recorded |
| Session protection | Logout prevents subsequent access to protected pages |

### Automated tests

Run the included unit tests, if present:

```powershell
python -m unittest discover -s tests -v
```

Record the actual test results before claiming that all tests have passed.

A passing unit test suite does not replace end-to-end testing, database testing, or a security review.

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
