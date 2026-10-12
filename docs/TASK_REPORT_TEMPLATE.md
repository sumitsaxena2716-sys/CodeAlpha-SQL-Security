# CodeAlpha Task 2 — Project Report

## Project Title
**CipherShield — Detecting Data Leaks Using SQL Injection**

## Objective
To develop a Flask and MySQL web application demonstrating SQL Injection prevention, sensitive-data encryption, secure authentication, and layered web application security controls.

## Technology Stack
- Python
- Flask
- MySQL
- HTML5 and CSS3
- Werkzeug password hashing
- AES-256-GCM encryption
- MySQL Connector/Python
- Python dotenv

## Core Modules
1. Secure user registration and login
2. Parameterized SQL queries
3. AES-256-GCM encryption for supported sensitive profile fields
4. CSRF protection for applicable form submissions
5. Temporary login throttling after repeated failed attempts
6. Security event logging
7. SQL Injection educational demonstration
8. Security Center for reviewing application events

## Implementation and Testing

The application was tested locally using Python, Flask, and MySQL.

Verified results:
- Database connection successful.
- Four automated login-throttling tests passed.
- Python syntax compilation completed successfully.
- SQL Injection demonstration input did not return unauthorized matching users.
- Authentication and security-event logging were exercised during local testing.
- Sensitive profile fields were saved in encrypted form and retrieved through the application.

## Testing Evidence

Attach screenshots of:
- User registration and login
- Dashboard
- MySQL records showing encrypted profile values
- SQL Injection demonstration result
- Security Center and security event logs
- Successful database connection
- Automated unit test results

Use dummy accounts and test data in screenshots. Hide passwords, secret keys, personal information, and other sensitive values.

## Deployment Status

The project has been developed and tested locally. AWS EC2 and Amazon RDS deployment has not been completed or verified. Cloud deployment documentation is included as a reference for future deployment.

## Result

CipherShield demonstrates practical web application security techniques, including parameterized SQL queries, password hashing, sensitive-data encryption, CSRF protection, login throttling, and security event logging.

The project is an educational security demonstration. The completed tests do not constitute a comprehensive penetration test or guarantee complete application security.