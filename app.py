"""
Remediated Flask REST API for Q4 (Part 3).

Fixes applied relative to the vulnerable scenario described in the
assignment (see README.md for the insecure "before" snippets):
  - Passwords are hashed with salted bcrypt (crypto_utils.py), not MD5.
  - All SQL uses parameterised queries — no string concatenation/f-strings
    ever touch the SQL text.
  - /admin requires a valid session token AND an is_admin flag (authN + authZ).
  - Secrets (SECRET_KEY, EXTERNAL_API_KEY) are loaded from environment
    variables via python-dotenv, never hardcoded.
"""
import os
import secrets
import sqlite3
import time
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, g, jsonify, request

from crypto_utils import hash_password, verify_password

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY")
EXTERNAL_API_KEY = os.environ.get("EXTERNAL_API_KEY")  # loaded, never hardcoded — see README Task 4

DATABASE_PATH = os.environ.get("DATABASE_PATH", "app.db")

# In-memory session store: token -> {username, is_admin, expires_at}.
# A real deployment would back this with Redis/DB so tokens survive a
# restart; kept in-memory here to keep the demo self-contained.
SESSIONS: dict[str, dict] = {}
SESSION_TTL_SECONDS = 3600


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    db = sqlite3.connect(DATABASE_PATH)
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    db.commit()
    db.close()


def require_admin(view):
    """Auth middleware for /admin — checks a valid, non-expired token AND is_admin.

    This is the Task 2 (Broken Access Control) remediation: the original
    /admin route had no check at all. A valid token alone is authentication
    (proves who you are); the is_admin check is authorization (proves you're
    allowed to be here) — both are required, since a regular authenticated
    user should still be rejected.
    """

    @wraps(view)
    def wrapped(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "missing bearer token"}), 401

        token = auth_header.removeprefix("Bearer ").strip()
        session = SESSIONS.get(token)
        if session is None or session["expires_at"] < time.time():
            return jsonify({"error": "invalid or expired token"}), 401
        if not session["is_admin"]:
            return jsonify({"error": "admin privileges required"}), 403

        g.current_user = session["username"]
        return view(*args, **kwargs)

    return wrapped


@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    password_hash = hash_password(password)
    db = get_db()
    try:
        # Parameterised query — username/password_hash are bound as data,
        # never interpolated into the SQL string. This is the Task 2 (SQL
        # Injection) remediation; see README.md for the insecure "before".
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "username already exists"}), 409

    return jsonify({"status": "registered", "username": username}), 201


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    db = get_db()
    row = db.execute(
        "SELECT username, password_hash, is_admin FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    if row is None or not verify_password(password, row["password_hash"]):
        return jsonify({"error": "invalid credentials"}), 401

    token = secrets.token_hex(32)
    SESSIONS[token] = {
        "username": row["username"],
        "is_admin": bool(row["is_admin"]),
        "expires_at": time.time() + SESSION_TTL_SECONDS,
    }
    return jsonify({"token": token, "expires_in": SESSION_TTL_SECONDS})


@app.get("/admin")
@require_admin
def admin():
    return jsonify({"status": "ok", "message": f"welcome, {g.current_user}"})


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    init_db()
    app.run(debug=False, port=5000)
