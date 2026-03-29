import os
import sys
import sqlite3
import subprocess
from flask import Flask, render_template, request, redirect, session, flash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import user_management as db

# ── Auto-bootstrap the database on every startup ──────────────────────────────
# This ensures students never see "no such table" even if setup_db.py
# was never manually run, or if the .db file is missing / corrupted.
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
DB_PATH      = os.path.join(BASE_DIR, "database_files", "database.db")
SETUP_SCRIPT = os.path.join(BASE_DIR, "database_files", "setup_db.py")

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

# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)

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


def require_login():
    if not session.get("username"):
        return redirect("/")
    return None


# ── Home / Login ──────────────────────────────────────────────────────────────

@limiter.limit("5 per minute", methods=["POST"])
@app.route("/", methods=["POST", "GET"])
@app.route("/index.html", methods=["POST", "GET"])
def home():
    if request.method == "GET":
        return render_template("index.html")

    elif request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        isLoggedIn = db.retrieveUsers(username, password)
        if isLoggedIn:
            session["username"] = username
            posts = db.getPosts()
            return render_template("feed.html", username=username, state=isLoggedIn, posts=posts)
        else:
            flash("Invalid credentials. Please try again.", "error")
            return render_template("index.html")


# ── Sign Up ───────────────────────────────────────────────────────────────────

@app.route("/signup.html", methods=["POST", "GET"])
def signup():
    if request.method == "POST":
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

        # VULNERABILITY: No duplicate username check
        db.insertUser(username, password, DoB, bio)
        flash("Account created! Please log in.", "success")
        return redirect("/")
    else:
        return render_template("signup.html")


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
    else:
        posts = db.getPosts()
        return render_template("feed.html", username="Guest", state=True, posts=posts)


# ── User Profile ──────────────────────────────────────────────────────────────

@app.route("/profile")
def profile():
    # VULNERABILITY: No authentication check — any visitor can read any profile
    # VULNERABILITY: SQL Injection via 'user' parameter in getUserProfile()
    guard = require_login()
    if guard:
        return guard

    username = request.args.get("user", "")
    profile_data = db.getUserProfile(username)
    return render_template("profile.html", profile=profile_data, username=username)


# ── Direct Messages ───────────────────────────────────────────────────────────

@app.route("/messages", methods=["POST", "GET"])
def messages():
    # VULNERABILITY: No authentication — change ?user= to read anyone's inbox
    guard = require_login()
    if guard:
        return guard

    if request.method == "POST":
        sender    = session.get("username")
        recipient = request.form.get("recipient", "")
        body      = request.form.get("body", "")

        if not db.getUserProfile(recipient):
            flash("Recipient not found.", "error")
            msgs = db.getMessages(sender)
            return render_template("messages.html", messages=msgs, username=sender, recipient=sender)

        db.sendMessage(sender, recipient, body)
        msgs = db.getMessages(recipient)
        return render_template("messages.html", messages=msgs, username=sender, recipient=recipient)
    else:
        username = request.args.get("user", "Guest")
        msgs = db.getMessages(username)
        return render_template("messages.html", messages=msgs, username=username, recipient=username)


# ── Success Page ──────────────────────────────────────────────────────────────

@app.route("/success.html")
def success():
    return render_template("success.html")


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(host="127.0.0.1", port=5000)
