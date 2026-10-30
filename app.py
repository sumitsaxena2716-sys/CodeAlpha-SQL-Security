import base64
import logging
import os
import re
import secrets
import time
from datetime import datetime
from functools import wraps

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv
from flask import (
    Flask,
    flash,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from database import (
    execute,
    fetch_one,
    fetch_all,
    get_cursor,
    get_db_connection,
    init_db,
)

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ERROR_TEMPLATE = "error.html"
PROFILE_TEMPLATE = "profile.html"
REGISTER_TEMPLATE = "register.html"
SECURITY_DEMO_TEMPLATE = "security_demo.html"
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

app = Flask(__name__)
_configured_secret = os.getenv("FLASK_SECRET_KEY", "").strip()
_is_production = (
    os.getenv("APP_ENV", os.getenv("FLASK_ENV", "development")).lower() == "production"
)
if _configured_secret == "replace-with-a-long-random-secret":
    _configured_secret = ""
if _is_production and (not _configured_secret or len(_configured_secret) < 32):
    raise RuntimeError(
        "Set a strong FLASK_SECRET_KEY of at least 32 characters "
        "before production deployment."
    )
if not _configured_secret:
    _configured_secret = secrets.token_urlsafe(48)
    _temporary_secret = True
else:
    _temporary_secret = False
app.config.update(
    SECRET_KEY=_configured_secret,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(os.getenv("COOKIE_SECURE", "0") == "1" or _is_production),
    MAX_CONTENT_LENGTH=1024 * 1024,
)

logging.basicConfig(
    filename=os.path.join(LOG_DIR, "security.log"),
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
if _temporary_secret:
    logging.warning(
        "FLASK_SECRET_KEY is not configured; using a temporary development key."
    )

# In-memory login throttling. For multi-instance production deployments,
# replace this with a shared store such as Redis.
LOGIN_BUCKET = {}
MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
LOCKOUT_SECONDS = int(os.getenv("LOCKOUT_SECONDS", "300"))


def _load_aes_key():
    raw = os.getenv("AES_256_KEY", "").strip()
    if not raw:
        return None

    try:
        key = base64.b64decode(
            raw.encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except ValueError:
        return None

    return key if len(key) == 32 else None


AES_KEY = _load_aes_key()
if _is_production and AES_KEY is None:
    raise RuntimeError("Set a valid AES_256_KEY before production deployment.")


def encrypt_sensitive(value: str) -> str:
    """Encrypt sensitive profile data using AES-256-GCM."""
    if not value:
        return ""
    if not AES_KEY:
        raise RuntimeError("AES_256_KEY is missing or invalid. Generate a 32-byte key.")
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(AES_KEY).encrypt(nonce, value.encode("utf-8"), None)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode("utf-8")


def decrypt_sensitive(token: str) -> str:
    if not token or not AES_KEY:
        return ""
    try:
        payload = base64.urlsafe_b64decode(token.encode("utf-8"))
        nonce, ciphertext = payload[:12], payload[12:]
        return AESGCM(AES_KEY).decrypt(nonce, ciphertext, None).decode("utf-8")
    except Exception:
        return "[encrypted]"


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.context_processor
def inject_site_metadata():
    return {
        "app_base_url": os.getenv("APP_BASE_URL", "").rstrip("/"),
        "current_year": datetime.now().year,
    }


@app.before_request
def protect_post_requests():
    # Let Flask return 404/405 for invalid routes or unsupported methods.
    if request.routing_exception is not None:
        return None

    if request.method == "POST":
        supplied = request.form.get("csrf_token", "")
        if not supplied or not secrets.compare_digest(
            supplied, session.get("csrf_token", "")
        ):
            logging.warning(
                "CSRF validation failed | path=%s | ip=%s",
                request.path,
                request.remote_addr,
            )
            response = make_response(
                render_template(
                    ERROR_TEMPLATE,
                    code=400,
                    message="Security validation failed. Please refresh and try again.",
                )
            )
            response.status_code = 400
            return response


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "object-src 'none'; "
        "script-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:;"
    )
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    return response


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def _login_key(username: str) -> str:
    """Use one consistent key for login throttling regardless of whitespace/case."""
    return (username or "").strip().casefold()


def is_locked(username: str) -> bool:
    key = _login_key(username)
    bucket = LOGIN_BUCKET.get(key)
    if not bucket:
        return False
    if bucket["locked_until"] > time.time():
        return True
    # Keep the bucket while it is below the limit; only expire a completed lock.
    if bucket["locked_until"]:
        LOGIN_BUCKET.pop(key, None)
    return False


def record_failed_login(username: str):
    key = _login_key(username)
    bucket = LOGIN_BUCKET.setdefault(key, {"attempts": 0, "locked_until": 0})
    bucket["attempts"] += 1
    if bucket["attempts"] >= MAX_LOGIN_ATTEMPTS:
        bucket["locked_until"] = time.time() + LOCKOUT_SECONDS
        logging.warning("Account temporarily rate-limited | username=%s", key)


def clear_login_attempts(username: str):
    LOGIN_BUCKET.pop(_login_key(username), None)


def record_event(event_type: str, username: str | None, status: str):
    try:
        execute(
            "INSERT INTO security_events (event_type, username, status) VALUES (%s, %s, %s)",
            (event_type, username, status),
            commit=True,
        )
    except Exception:
        logging.exception("Security event write failed")


def get_current_user():
    if "user_id" not in session:
        return None
    user = fetch_one(
        "SELECT id, username, email, phone_encrypted, security_note_encrypted, created_at FROM users WHERE id = %s",
        (session["user_id"],),
    )
    if user:
        user["phone"] = decrypt_sensitive(user.get("phone_encrypted"))
        user["security_note"] = decrypt_sensitive(user.get("security_note_encrypted"))
    return user


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", user=get_current_user())


def _registration_validation_error(email: str, password: str, phone: str, note: str):
    """Return the first registration validation message, or None when valid."""
    if len(email) > 150 or not re.fullmatch(
        r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@" r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+",
        email,
    ):
        return "Enter a valid email address."
    if not 8 <= len(password) <= 128:
        return "Password must contain 8â€“128 characters."
    if len(note) > 500:
        return "Security note must be 500 characters or fewer."
    if phone and not re.fullmatch(r"\+?[0-9 ()-]{7,20}", phone):
        return "Enter a valid phone number with 7â€“20 characters."
    return None


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        phone = request.form.get("phone", "").strip()
        note = request.form.get("security_note", "").strip()

        validation_error = _registration_validation_error(email, password, phone, note)
        if validation_error:
            flash(validation_error, "danger")
            return render_template(REGISTER_TEMPLATE), 400

        # Require AES encryption configuration
        if not AES_KEY:
            flash(
                "AES-256 encryption is not configured. "
                "Set AES_256_KEY in .env first.",
                "danger",
            )
            return render_template(REGISTER_TEMPLATE)

        try:
            password_hash = generate_password_hash(password)
            phone_encrypted = encrypt_sensitive(phone)
            note_encrypted = encrypt_sensitive(note)

            with get_cursor() as (connection, cursor):
                cursor.execute(
                    """
                    INSERT INTO users (
                        username,
                        email,
                        password_hash,
                        phone_encrypted,
                        security_note_encrypted
                    )
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        username,
                        email,
                        password_hash,
                        phone_encrypted,
                        note_encrypted,
                    ),
                )
                connection.commit()

            logging.info(
                "Registration success | username=%s | ip=%s",
                username,
                request.remote_addr,
            )
            record_event("REGISTRATION", username, "SUCCESS")
            flash("Account created securely. You can now sign in.", "success")
            return redirect(url_for("login"))

        except Exception:
            logging.exception("Registration failed | username=%s", username)
            record_event("REGISTRATION", username, "FAILED")
            flash(
                "Registration failed. Username or email may already exist.",
                "danger",
            )

    return render_template(REGISTER_TEMPLATE)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if is_locked(username):
            flash("Too many failed attempts. Try again later.", "danger")
            return render_template("login.html")

        try:
            user = fetch_one(
                "SELECT id, username, password_hash FROM users WHERE username = %s",
                (username,),
            )
            if user and check_password_hash(user["password_hash"], password):
                clear_login_attempts(username)
                session.clear()
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["csrf_token"] = secrets.token_urlsafe(32)
                logging.info(
                    "Login success | username=%s | ip=%s", username, request.remote_addr
                )
                record_event("LOGIN", username, "SUCCESS")
                return redirect(url_for("dashboard"))
            else:
                record_failed_login(username)

                logging.warning(
                    "Login failed | username=%s | ip=%s", username, request.remote_addr
                )
                record_event("LOGIN", username, "FAILED")
                flash("Invalid username or password.", "danger")

        except Exception:
            logging.exception("Login database error")
            record_event("LOGIN", username, "ERROR")
            flash("Unable to process login right now.", "danger")

    return render_template("login.html")


@app.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    user = get_current_user()
    return render_template("dashboard.html", user=user)


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = get_current_user()
    if request.method == "POST":
        phone = request.form.get("phone", "").strip()
        note = request.form.get("security_note", "").strip()
        if phone and not re.fullmatch(r"\+?[0-9 ]{7,20}", phone):
            flash(
                "Enter a phone number with 7â€“20 digits, spaces, and an optional leading +.",
                "danger",
            )
            return render_template(PROFILE_TEMPLATE, user=user), 400
        if len(note) > 500:
            flash("Private security note must be 500 characters or fewer.", "danger")
            return render_template(PROFILE_TEMPLATE, user=user), 400
        try:
            execute(
                "UPDATE users SET phone_encrypted = %s, security_note_encrypted = %s WHERE id = %s",
                (encrypt_sensitive(phone), encrypt_sensitive(note), session["user_id"]),
                commit=True,
            )
            logging.info(
                "Encrypted profile updated | username=%s", session.get("username")
            )
            record_event("PROFILE_ENCRYPTED_UPDATE", session.get("username"), "SUCCESS")
            flash(
                "Sensitive profile fields were encrypted with AES-256-GCM and saved.",
                "success",
            )
            return redirect(url_for("profile"))
        except Exception:
            logging.exception("Profile update failed")
            flash("Profile could not be updated.", "danger")
    return render_template(PROFILE_TEMPLATE, user=user)


@app.route("/security-demo", methods=["GET"])
def security_demo():
    return render_template(SECURITY_DEMO_TEMPLATE)


@app.route("/security-center", methods=["GET"])
@login_required
def security_center():
    # Show only this signed-in accountâ€™s events; never expose other usersâ€™ activity.
    rows = fetch_all(
        "SELECT event_time, event_type, username, status FROM security_events WHERE username = %s ORDER BY id DESC LIMIT 20",
        (session.get("username"),),
    )
    return render_template("security_center.html", events=rows)


@app.route("/security-demo/test", methods=["POST"])
def security_demo_test():
    """Safe educational test: the supplied text is only passed as a parameter.
    It never executes attacker-controlled SQL and never targets external systems.
    """
    sample = request.form.get("sample", "")[:120]
    try:
        # Intentionally parameterized. This is the behavior being demonstrated.
        result = fetch_one(
            "SELECT COUNT(*) AS user_count FROM users WHERE username = %s",
            (sample,),
        )
        return render_template(
            SECURITY_DEMO_TEMPLATE,
            test_value=sample,
            test_result=result["user_count"] if result else 0,
        )
    except Exception:
        logging.exception("Security demo test failed")
        response = make_response(
            render_template(SECURITY_DEMO_TEMPLATE, test_value=sample, test_error=True)
        )
        response.status_code = 503
        return response


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    username = session.get("username")
    session.clear()
    if username:
        logging.info("Logout | username=%s", username)
        record_event("LOGOUT", username, "SUCCESS")
    return redirect(url_for("index"))


@app.route("/privacy", methods=["GET"])
def privacy():
    return render_template("privacy.html")


@app.route("/terms", methods=["GET"])
def terms():
    return render_template("terms.html")


@app.route("/robots.txt", methods=["GET"])
def robots_txt():
    from flask import Response

    base = os.getenv("APP_BASE_URL", "").rstrip("/")
    body = "User-agent: *\nAllow: /\nDisallow: /dashboard\nDisallow: /profile\nDisallow: /security-center\nDisallow: /login\nDisallow: /register\nDisallow: /logout\n"
    if base:
        body += f"Sitemap: {base}/sitemap.xml\n"
    return Response(body, mimetype="text/plain")


@app.route("/sitemap.xml", methods=["GET"])
def sitemap_xml():
    from flask import Response

    base = os.getenv("APP_BASE_URL", "").rstrip("/")
    if not base:
        return Response(
            "APP_BASE_URL is not configured; sitemap is unavailable.\n",
            status=503,
            mimetype="text/plain",
        )
    urls = ["/", "/security-demo", "/privacy", "/terms"]
    entries = "".join(f"<url><loc>{base}{path}</loc></url>" for path in urls)
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        + '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        + entries
        + "</urlset>"
    )
    return Response(xml, mimetype="application/xml")


@app.errorhandler(404)
def not_found(_error):
    response = make_response(
        render_template(
            ERROR_TEMPLATE, code=404, message="The requested page could not be found."
        )
    )
    response.status_code = 404
    return response


@app.errorhandler(413)
def request_too_large(_error):
    response = make_response(
        render_template(
            ERROR_TEMPLATE,
            code=413,
            message="The submitted request is too large. Reduce the form input and try again.",
        )
    )
    response.status_code = 413
    return response


@app.errorhandler(500)
def server_error(_error):
    logging.exception("Unhandled server error")
    response = make_response(
        render_template(
            ERROR_TEMPLATE,
            code=500,
            message="An internal error occurred. No sensitive details were exposed.",
        )
    )
    response.status_code = 500
    return response


if __name__ == "__main__":
    if os.getenv("AUTO_INIT_DB", "1") == "1":
        try:
            init_db()
        except Exception:
            logging.exception("Database initialization failed")
            raise SystemExit(
                "Database initialization failed. Check MySQL service and .env settings; see logs/security.log for details."
            )
    app.run(
        host=os.getenv("FLASK_HOST", "127.0.0.1"),
        port=int(os.getenv("FLASK_PORT", "5000")),
        debug=False,
    )
