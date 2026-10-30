# SonarCloud Remediation Notes

## 1. Code Changes Applied

The following code-quality and security-related changes have been applied:

- Docker image uses `--only-binary=:all:`.
- Docker image copies only the application files required at runtime.
- Gunicorn runs as a non-root user.
- Flask routes that only serve pages explicitly declare `methods=["GET"]`.
- Repeated template names are defined as constants in `app.py`.
- Exception handlers use `logging.exception()` where traceback information is useful.
- Phone validation uses deterministic character checks instead of a backtracking regular expression.
- Flash messages use an `<output>` element instead of `role="status"`.
- PowerShell conditions use `-not` instead of `!`.
- Registration validation and request handling have been corrected.
- Security tests cover CSRF protection, access control, SQL injection handling, security headers, login throttling, and database configuration.

## 2. Dependency and CI Improvements

The project now includes:

- `requirements-lock.txt`
- `requirements-dev-lock.txt`
- `.github/workflows/main.yml`

Both lock files contain SHA-256 hashes and have been tested locally using:

```powershell
python -m pip install --only-binary=:all: --require-hashes -r requirements-lock.txt
```

```powershell
python -m pip install --only-binary=:all: --require-hashes -r requirements-dev-lock.txt
```

The GitHub Actions workflow:
- Runs on pushes and pull requests targeting `main`.
- Uses Python 3.12.
- Installs dependencies using hash-verified lock files.
- Runs the test suite using `unittest discover`.

The workflow configuration has been inspected, and its equivalent test command has passed locally. A successful remote GitHub Actions run is still pending.

## 3. Local Verification Results

The following checks have been completed locally:

| Verification | Result |
|---|---|
| Automated test suite | 62 passed, 0 failed |
| Python 3.12.10 | 62 tests passed |
| Python 3.13.17 | 62 tests passed |
| `app.py` coverage | 95% |
| `database.py` coverage | 100% |
| Overall code coverage | 96% |
| Python compilation | Passed |
| Dependency vulnerability audit | No known vulnerabilities found |
| Hash-verified dependency installation | Passed |
| Git whitespace check | No whitespace errors |

### Commands used

```powershell
python -m pytest -v
```

```powershell
python -m pytest --cov=app --cov=database --cov-report=term-missing
```

```powershell
python -m compileall -q app.py database.py tests
```

```powershell
python -m pip_audit -r requirements.txt
```

```powershell
git diff --check
```

## 4. Pending Verification

The following items have not yet been confirmed:

- Remote GitHub Actions workflow execution after pushing the changes.
- Fresh SonarCloud analysis.
- SonarCloud Quality Gate result after the latest changes.
- Final review of the repository before commit and push.

## 5. Important Notes

Local unit tests and static checks do not guarantee that the application is completely secure.

A passing unit test suite does not replace end-to-end testing, database integration testing, deployment verification, or an independent security assessment.

SonarCloud findings should be considered resolved only after a fresh analysis confirms the updated results.