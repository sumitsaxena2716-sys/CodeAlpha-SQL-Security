# CipherShield — CodeAlpha Cloud Computing Task 2

**Detecting Data Leaks Using SQL Injection**

CipherShield is a cloud-ready Flask + MySQL security application designed around CodeAlpha's Task 2 requirements. It demonstrates secure authentication, parameterized SQL queries, AES-256-GCM encryption for sensitive profile data, CSRF protection, login throttling, security headers, security logging and a controlled SQL Injection education lab.

## Task 2 requirement mapping

| CodeAlpha requirement | Implementation |
|---|---|
| Secure a cloud system against SQL Injection | Parameterized MySQL queries throughout the application |
| AES-256 encryption | AES-256-GCM for optional phone/private profile data |
| Secure SQL injection testing capability | Controlled `/security-demo` test that never executes raw user SQL |
| Double-layer security | Query layer + encrypted data layer, plus authentication/web controls |
| Internet accessibility | App binds to `0.0.0.0`; AWS EC2 + RDS deployment guide included |

> Passwords are **hashed**, not reversibly encrypted. AES-256-GCM is used for sensitive profile fields where reversible encryption is appropriate.

## Features

- Modern responsive cybersecurity UI with one consistent theme
- Registration and secure login
- Werkzeug password hashing
- Parameterized SQL queries
- AES-256-GCM encrypted profile fields
- CSRF protection for POST requests
- Login throttling after repeated failures
- Security headers including CSP, X-Frame-Options and HSTS when HTTPS is active
- Security event center
- Controlled SQL Injection demonstration
- MySQL / AWS RDS compatible database layer
- `.env` based secrets management
- Production-style `0.0.0.0` binding
- AWS EC2 + RDS deployment documentation

## Project structure

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
│   └── AWS_EC2_RDS_DEPLOYMENT.md
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

## Local setup

### 1. Create a virtual environment

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 2. Install packages

```powershell
python -m pip install -r requirements.txt
```

### 3. Create the database

Open MySQL Workbench and run:

```sql
SOURCE schema.sql;
```

Or paste the contents of `schema.sql` into MySQL Workbench and execute it.

### 4. Create `.env`

Copy `.env.example` to `.env` and set your MySQL credentials.

Generate an AES-256 key:

```powershell
python generate_key.py
```

Copy the printed value into `AES_256_KEY` in `.env`.

Generate a strong Flask secret as well, for example:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

### 5. Test the database

```powershell
python test_db.py
```

Expected:

```text
Database connection: SUCCESS
Database: codealpha_security
```

### 6. Run

```powershell
python app.py
```

Open:

`http://127.0.0.1:5000`

## Demonstrating Task 2

1. Open **Create secure account**.
2. Register a test user.
3. Log in and open **Dashboard**.
4. Open **Protected profile** and save a phone/private note.
5. In MySQL, inspect the row. The password is a hash and the sensitive profile fields are encrypted ciphertext.
6. Open **Security Lab**.
7. Submit the default test string or another harmless string. The server uses a parameterized query and never concatenates it into SQL.
8. Open **Security Center** to see authentication/profile security events.

## AWS cloud deployment

See `docs/AWS_EC2_RDS_DEPLOYMENT.md` for the complete EC2 + RDS deployment path. The application is already configured to bind to `0.0.0.0` and read the RDS endpoint from `DB_HOST`.

For an internet-facing deployment, use HTTPS behind a reverse proxy/load balancer and set:

```text
COOKIE_SECURE=1
```

Do not expose MySQL/RDS port 3306 publicly. Allow it only from the application server's security group.

## Security notes

- Never commit `.env` or production credentials.
- Never use `debug=True` on an internet-facing deployment.
- Rotate `AES_256_KEY` only with a planned data re-encryption strategy; changing it without re-encrypting existing values makes them unreadable.
- The in-memory login throttle is suitable for a single app instance/demo. For multiple EC2 instances, use a shared store such as Redis.
- The SQL Injection lab is intentionally limited to the application's own database and safe parameterized queries.
