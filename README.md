# CodeAlpha - SQL Injection & Data Leak Prevention

A local Flask + MySQL security project for demonstrating secure authentication and SQL Injection prevention.

## Features

- User registration
- Password hashing with Werkzeug
- Secure login
- Parameterized SQL queries
- Generic error messages
- Security logging
- Session-based authentication
- Local SQL Injection prevention demonstration
- Clean documentation

## Requirements

- Python 3.x
- MySQL 8.x
- Existing MySQL database: `codealpha_security`

## Setup

1. Activate your virtual environment.
2. Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

3. Create `.env` from `.env.example` and put your local MySQL password in it.
4. If the database/table does not exist, run `schema.sql` in MySQL Workbench.
5. Test the database:

```powershell
python test_db.py
```

6. Start the Flask application:

```powershell
python app.py
```

7. Open:

`http://127.0.0.1:5000`

## Security Design

The application uses parameterized queries such as:

```python
cursor.execute(
    "SELECT id, username, password_hash FROM users WHERE username = %s",
    (username,),
)
```

The application never builds SQL by concatenating raw form input.

Passwords are never stored as plaintext. They are stored as hashes using Werkzeug's password hashing helpers.

The application also avoids exposing database exception details to normal users.

## SQL Injection demonstration

The `/security-demo` page explains the difference between an unsafe query pattern and the parameterized query used by this project. The demo is intentionally local and educational; it does not target any external system.

## GitHub safety

Do not commit `.env`. It contains local credentials. The included `.gitignore` excludes it.
