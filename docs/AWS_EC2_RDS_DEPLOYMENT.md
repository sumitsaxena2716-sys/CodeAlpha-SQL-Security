# AWS EC2 + RDS Deployment Guide

This guide turns the local Flask/MySQL application into the cloud-hosted version required by CodeAlpha Task 2.

## Architecture

```text
Internet User
     |
     v
HTTPS / Domain
     |
     v
AWS EC2 (Flask + Gunicorn)
     |
     | private DB connection
     v
AWS RDS for MySQL
```

## 1. Create an RDS MySQL database

- Create an Amazon RDS MySQL instance.
- Use a strong master password.
- Prefer **private access** where possible.
- Put RDS and EC2 in the same VPC.
- RDS security group: allow TCP `3306` only from the EC2 security group, not from `0.0.0.0/0`.

After creation, copy the RDS endpoint into `DB_HOST`.

## 2. Create an EC2 instance

Use a small Linux instance suitable for a student/demo workload.

Security group recommendations:

- SSH `22`: your own IP only
- HTTP `80`: internet if using HTTP for initial setup
- HTTPS `443`: internet for production
- Do **not** expose MySQL `3306` from the EC2 security group to the internet.

## 3. Install Python and MySQL client dependencies

On the EC2 Linux host:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip nginx
```

Clone or copy this project to the server.

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
autopep8 --version 2>/dev/null || true
```

The last line is optional and only confirms whether an existing formatter is available.

## 4. Configure environment variables

Create `.env` on the server. Never put production secrets in GitHub.

```text
FLASK_SECRET_KEY=<strong-random-secret>
FLASK_HOST=0.0.0.0
FLASK_PORT=5000
COOKIE_SECURE=1
AUTO_INIT_DB=1
DB_HOST=<your-rds-endpoint>
DB_PORT=3306
DB_USER=<rds-user>
DB_PASSWORD=<rds-password>
DB_NAME=codealpha_security
AES_256_KEY=<generated-32-byte-base64-key>
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_SECONDS=300
```

Generate the AES key locally with:

```bash
python3 generate_key.py
```

## 5. Initialize the schema

Run `schema.sql` against RDS using MySQL Workbench, the MySQL CLI, or another trusted database client.

Then verify from EC2:

```bash
python3 test_db.py
```

## 6. Production application server

Install Gunicorn:

```bash
pip install gunicorn
```

Test:

```bash
gunicorn --bind 0.0.0.0:5000 app:app
```

## 7. Nginx reverse proxy

Configure Nginx to proxy the public site to `127.0.0.1:5000` and terminate HTTPS.

For a real deployment, use a domain and a trusted TLS certificate. After HTTPS is active, keep `COOKIE_SECURE=1`.

## 8. Keep the app running

A systemd service can run Gunicorn automatically. Example service:

```ini
[Unit]
Description=CipherShield Flask Application
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/home/ubuntu/CodeAlpha_SQL_Security_Task2
EnvironmentFile=/home/ubuntu/CodeAlpha_SQL_Security_Task2/.env
ExecStart=/home/ubuntu/CodeAlpha_SQL_Security_Task2/venv/bin/gunicorn --workers 2 --bind 127.0.0.1:5000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable ciphershield
sudo systemctl start ciphershield
sudo systemctl status ciphershield
```

## 9. Task 2 verification checklist

- [ ] Public HTTPS page opens from another device/network.
- [ ] Registration works.
- [ ] Login works.
- [ ] Password is stored as a hash.
- [ ] Sensitive profile data is AES-256-GCM ciphertext in RDS.
- [ ] SQL Injection test input does not bypass authentication.
- [ ] Security headers are present.
- [ ] RDS 3306 is not public.
- [ ] `.env` is not in the repository.
- [ ] Debug mode is disabled.
- [ ] Security events are visible in Security Center.
