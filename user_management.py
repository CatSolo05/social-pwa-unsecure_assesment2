import bcrypt
import sqlite3 as sql
import time
import random
import os
  
        

# ─────────────────────────────────────────────────────────────────────────────
#  user_management.py
#  Handles all direct database operations for the Unsecure Social PWA.
#
#  Database access helpers for the Social PWA.
# ─────────────────────────────────────────────────────────────────────────────

# Absolute paths — works regardless of where `python main.py` is called from
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, "database_files", "database.db")
LOG_PATH = os.path.join(BASE_DIR, "visitor_log.txt")
DUMMY_PASSWORD_HASH = "$2b$12$QF4gq2rqfU9Y6n7M6fXV4e1bQdN9cW0x4uA8Qx5Q1hA0mAq4cF3QK"


def insertUser(username, password, DoB, bio=""):
    """
    Insert a new user.
    Passwords are stored as bcrypt hashes.
    """
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(
        "INSERT INTO users (username, password, dateOfBirth, bio) VALUES (?,?,?,?)",
        (username, password_hash, DoB, bio),
    )
    con.commit()
    con.close()


def userExists(username):
    """Return True when a username is already present."""
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    con.close()
    return row is not None


def retrieveUsers(username, password):
    """
    Authenticate a user.
    Fetch the user by username and verify the submitted password against the
    stored bcrypt hash. A dummy hash is used for nonexistent users so the
    response time does not reveal whether an account exists.
    """
    con = sql.connect(DB_PATH)
    cur = con.cursor()

    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    user_row = cur.fetchone()
    con.close()

    stored_hash = user_row[2] if user_row is not None else DUMMY_PASSWORD_HASH
    password_matches = bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))

    try:
        with open(LOG_PATH, "r") as f:
            count = int(f.read().strip() or 0)
        with open(LOG_PATH, "w") as f:
            f.write(str(count + 1))
    except Exception:
        pass

    return user_row is not None and password_matches


def insertPost(author, content):
    """
    Insert a post.
    VULNERABILITY: SQL Injection via f-string on both author and content.
    VULNERABILITY: author comes from a hidden HTML field — easily spoofed (IDOR).
    """
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("INSERT INTO posts (author, content) VALUES (?, ?)", (author, content))
    con.commit()
    con.close()


def getPosts():
    """
    Get all posts newest-first.
    NOTE: Content returned here is rendered with |safe in feed.html — stored XSS.
    """
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    data = cur.execute("SELECT * FROM posts ORDER BY id DESC").fetchall()
    con.close()
    return data


def getUserProfile(username):
    """
    Get a user profile row.
    """
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT id, username, dateOfBirth, bio, role FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    con.close()
    return row


def getMessages(username):
    """
    Get inbox for a user.
    """
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT * FROM messages WHERE recipient = ? ORDER BY id DESC", (username,))
    rows = cur.fetchall()
    con.close()
    return rows


def sendMessage(sender, recipient, body):
    """
    Send a DM.
    VULNERABILITY: SQL Injection on all three fields.
    VULNERABILITY: sender taken from hidden form field — can be spoofed.
    """
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("INSERT INTO messages (sender, recipient, body) VALUES (?, ?, ?)", (sender, recipient, body))
    con.commit()
    con.close()


def getVisitorCount():
    """Return login attempt count."""
    try:
        with open(LOG_PATH, "r") as f:
            return int(f.read().strip() or 0)
    except Exception:
        return 0
