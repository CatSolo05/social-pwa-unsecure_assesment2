import os
import sys
import sqlite3
import subprocess
from flask import Flask, jsonify, render_template, request, redirect, session, flash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, generate_csrf
import user_management as db

# ── Auto-bootstrap the database on every startup ──────────────────────────────
# This ensures students never see "no such table" even if setup_db.py
# was never manually run, or if the .db file is missing / corrupted.
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
DB_PATH      = os.path.join(BASE_DIR, "database_files", "database.db")
SETUP_SCRIPT = os.path.join(BASE_DIR, "database_files", "setup_db.py")
ENV_PATH     = os.path.join(BASE_DIR, ".env")
DEFAULT_VAPID_PUBLIC_KEY = (
    "BEl62iUYgUivxIkv69yViEuiBIa-Ib9-SkvMeAtA3LFgDzkrxZJjSgSnfckjBJuBkr3qBUYIHBQFLXYp5Nksh8U"
)


def load_env_file():
    if not os.path.exists(ENV_PATH):
        return

    with open(ENV_PATH, "r", encoding="utf-8") as env_file:
        for raw_line in env_file:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)

def _tables_exist():
    """Return True if the required tables are all present."""
    try:
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        tables = {r[0] for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        con.close()
        return {"users", "posts", "messages"}.issubset(tables)
    except Exception:
        return False

def init_db():
    os.makedirs(os.path.join(BASE_DIR, "database_files"), exist_ok=True)
    if not os.path.exists(DB_PATH) or not _tables_exist():
        print("[SocialPWA] Setting up database...")
        result = subprocess.run(
            [sys.executable, SETUP_SCRIPT],
            capture_output=True, text=True
        )
        print(result.stdout)
        if result.returncode != 0:
            print("[SocialPWA] WARNING: setup_db failed:", result.stderr)
    else:
        print("[SocialPWA] Database already exists — skipping setup.")

init_db()
load_env_file()

# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

csrf = CSRFProtect(app)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],
)

# SECRET_KEY must be provided via environment variable.
app.secret_key = os.environ.get("SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("SECRET_KEY environment variable is not set.")

app.config["VAPID_PUBLIC_KEY"] = os.environ.get(
    "VAPID_PUBLIC_KEY", DEFAULT_VAPID_PUBLIC_KEY
)


@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "object-src 'none'; "
        "base-uri 'self'"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"

    if not request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

    return response


def require_login():
    if not session.get("username"):
        return redirect("/")
    return None


def current_username():
    return session.get("username", "")


@app.context_processor
def inject_client_config():
    return {"vapid_public_key": app.config.get("VAPID_PUBLIC_KEY", "")}


@app.route("/csrf-token")
def csrf_token_route():
    return jsonify({"csrfToken": generate_csrf()})


# ── Home / Login ──────────────────────────────────────────────────────────────

@limiter.limit("5 per minute", methods=["POST"])
@app.route("/", methods=["POST", "GET"])
@app.route("/index.html", methods=["POST", "GET"])
def home():
    if request.method != "POST":
        return render_template("index.html")

    username = request.form["username"]
    password = request.form["password"]
    isLoggedIn = db.retrieveUsers(username, password)
    if isLoggedIn:
        session["username"] = username
        return redirect("/feed.html")

    flash("Invalid credentials. Please try again.", "error")
    return redirect("/")


# ── Sign Up ───────────────────────────────────────────────────────────────────

@app.route("/signup.html", methods=["POST", "GET"])
def signup():
    if request.method != "POST":
        return render_template("signup.html")

    username = request.form["username"]
    password = request.form["password"]
    DoB      = request.form["dob"]
    bio      = request.form.get("bio", "")

    weak_passwords = {
        "password",
        "password123",
        "12345678",
        "qwerty",
        "letmein",
        "admin123",
        "welcome123",
    }

    if password.lower() in weak_passwords:
        flash("Please choose a stronger password.", "error")
        return redirect("/signup.html")

    if len(password) < 8:
        flash("Password must be at least 8 characters long.", "error")
        return redirect("/signup.html")

    if db.userExists(username):
        flash("That username is already taken.", "error")
        return redirect("/signup.html")

    db.insertUser(username, password, DoB, bio)
    flash("Account created! Please log in.", "success")
    return redirect("/")


# ── Social Feed ───────────────────────────────────────────────────────────────

@app.route("/feed.html", methods=["POST", "GET"])
def feed():
    guard = require_login()
    if guard:
        return guard

    if request.method == "POST":
        post_content = request.form["content"]
        username = session.get("username")
        db.insertPost(username, post_content)
        posts = db.getPosts()
        return render_template("feed.html", username=username, state=True, posts=posts)

    posts = db.getPosts()
    username = session.get("username", "Guest")
    return render_template("feed.html", username=username, state=True, posts=posts)


# ── User Profile ──────────────────────────────────────────────────────────────

@app.route("/profile")
def profile():
    guard = require_login()
    if guard:
        return guard

    username = current_username()
    profile_data = db.getUserProfile(username)
    return render_template("profile.html", profile=profile_data, username=username)


# ── Direct Messages ───────────────────────────────────────────────────────────

@app.route("/messages", methods=["POST", "GET"])
def messages():
    guard = require_login()
    if guard:
        return guard

    username = current_username()

    if request.method == "POST":
        sender    = username
        recipient = request.form.get("recipient", "")
        body      = request.form.get("body", "")

        if not db.getUserProfile(recipient):
            flash("Recipient not found.", "error")
            msgs = db.getMessages(sender)
            return render_template("messages.html", messages=msgs, username=sender, recipient=sender)

        db.sendMessage(sender, recipient, body)
        msgs = db.getMessages(sender)
        flash("Message sent.", "success")
        return render_template("messages.html", messages=msgs, username=sender, recipient=recipient)

    msgs = db.getMessages(username)
    recipient = request.args.get("recipient", "")
    return render_template("messages.html", messages=msgs, username=username, recipient=recipient)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect("/")


# ── Success Page ──────────────────────────────────────────────────────────────

@app.route("/success.html")
def success():
    return render_template("success.html")


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
