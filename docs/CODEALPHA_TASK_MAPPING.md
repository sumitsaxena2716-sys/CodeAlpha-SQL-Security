# CodeAlpha Task 2 — Requirement Mapping

## 1. Secure cloud system against SQL Injection

The application uses parameterized SQL everywhere user input reaches MySQL. Example:

```python
cursor.execute(
    "SELECT id, username, password_hash FROM users WHERE username = %s",
    (username,),
)
```

Raw form input is never concatenated into SQL statements.

## 2. AES-256 encryption

Sensitive profile values are protected with AES-256-GCM using the `cryptography` package. The key is supplied through `AES_256_KEY` and is not stored in source code.

Passwords are intentionally hashed rather than encrypted because passwords should not be recoverable.

## 3. Secure SQL Injection test capability

`/security-demo` provides an educational test. The submitted sample is passed as a parameter to a harmless `COUNT` query. The application does not provide a raw-SQL execution endpoint and does not target external systems.

## 4. Double-layer security protocol

**Layer 1 — Query security:** parameterized SQL prevents input from changing SQL syntax.

**Layer 2 — Data security:** AES-256-GCM protects selected sensitive values at rest.

Additional controls include password hashing, CSRF protection, login throttling, secure cookies and security response headers.

## 5. Internet accessibility

The Flask server binds to `0.0.0.0`, making it suitable for an EC2 instance. The deployment guide configures MySQL through AWS RDS and explains how to expose the application through a web-facing EC2 instance.
