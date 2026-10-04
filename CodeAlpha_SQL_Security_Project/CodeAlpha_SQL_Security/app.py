import os
import logging
from datetime import datetime
from functools import wraps

from flask import Flask, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from database import get_db_connection

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "change-this-development-secret")

LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    filename=os.path.join(LOG_DIR, "security.log"),
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if len(username) < 3 or len(username) > 100:
            flash("Username must be between 3 and 100 characters.", "danger")
            return render_template("register.html")

        if "@" not in email or len(email) > 150:
            flash("Please enter a valid email address.", "danger")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "danger")
            return render_template("register.html")

        password_hash = generate_password_hash(password)

        try:
            connection = get_db_connection()
            cursor = connection.cursor()
            # Parameterized query: user input is never concatenated into SQL.
            cursor.execute(
                """
                INSERT INTO users (username, email, password_hash)
                VALUES (%s, %s, %s)
                """,
                (username, email, password_hash),
            )
            connection.commit()
            cursor.close()
            connection.close()

            logging.info("User registration succeeded for username=%s", username)
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))

        except Exception as exc:
            logging.warning("Registration failed for username=%s: %s", username, exc)
            flash("Registration failed. Username or email may already exist.", "danger")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        try:
            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)

            # Parameterized SELECT prevents SQL injection.
            cursor.execute(
                "SELECT id, username, password_hash FROM users WHERE username = %s",
                (username,),
            )
            user = cursor.fetchone()

            cursor.close()
            connection.close()

            if user and check_password_hash(user["password_hash"], password):
                session.clear()
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                logging.info("Successful login for username=%s", username)
                return redirect(url_for("dashboard"))

            logging.warning("Failed login attempt for username=%s", username)
            flash("Invalid username or password.", "danger")

        except Exception as exc:
            logging.error("Login database error: %s", exc)
            flash("Unable to process login right now.", "danger")

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", username=session["username"])


@app.route("/logout")
def logout():
    username = session.get("username")
    session.clear()
    if username:
        logging.info("Logout for username=%s", username)
    return redirect(url_for("index"))


@app.route("/security-demo")
def security_demo():
    return render_template("security_demo.html")


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="Page not found."), 404


@app.errorhandler(500)
def server_error(_error):
    logging.exception("Unhandled server error")
    return render_template(
        "error.html",
        code=500,
        message="An internal error occurred. Details are not exposed to the user.",
    ), 500


if __name__ == "__main__":
    app.run(debug=True)
