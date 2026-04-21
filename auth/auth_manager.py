"""
auth_manager.py — Authentication with:
  • Password policy enforcement
  • Brute-force login protection
  • Account types: personal / company
  • Role support: user / admin
  • Input sanitization on all fields
  • Secure password hashing (SHA-256 + salt)
"""
import hashlib
import secrets
import random
import re

from database.db_manager import (
    create_user, get_user_by_username_or_email,
    email_exists, username_exists, record_login_attempt,
    update_last_login, is_user_active
)
from utils.security import (
    validate_password, sanitize_username, sanitize_email,
    sanitize_text, check_login_allowed, record_failed_login,
    record_successful_login, generate_auth_code
)


# ── Password Hashing ──────────────────────────────────────────────────────────

def _hash_password(password: str) -> str:
    """Hash password with random salt using SHA-256."""
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return f"{salt}:{hashed}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a stored salt:hash string."""
    try:
        salt, hashed = stored_hash.split(":", 1)
        candidate = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
        return secrets.compare_digest(candidate, hashed)
    except Exception:
        return False


def hash_password_for_update(new_password: str) -> str:
    """Public wrapper for hashing — used when admin/user changes password."""
    return _hash_password(new_password)


# ── Captcha ───────────────────────────────────────────────────────────────────

def generate_captcha() -> tuple:
    """Returns (question_str, answer_int)."""
    a = random.randint(2, 20)
    b = random.randint(2, 20)
    ops = [
        (f"{a} + {b}",          a + b),
        (f"{max(a,b)} - {min(a,b)}", max(a,b) - min(a,b)),
        (f"{a} × {b}",          a * b),
    ]
    return random.choice(ops)


# ── Registration ──────────────────────────────────────────────────────────────

def register(
    username: str,
    email: str,
    password: str,
    confirm_password: str,
    account_type: str = "personal",
    manager_email: str = "",
    smtp_sender_email: str = "",
    smtp_app_password: str = "",
) -> tuple:
    """
    Register a new user.
    account_type: "personal" or "company"
    manager_email: required for company accounts.
    Returns (success: bool, message: str)
    """
    # ── Sanitize inputs ──
    username, err = sanitize_username(username)
    if err:
        return False, err

    email, err = sanitize_email(email)
    if err:
        return False, err

    # ── Password policy ──
    ok, err = validate_password(password.strip())
    if not ok:
        return False, err

    if password.strip() != confirm_password.strip():
        return False, "Passwords do not match."

    # ── Account type validation ──
    if account_type not in ("personal", "company"):
        return False, "Invalid account type."

    mgr_email_clean = ""
    if account_type == "company":
        mgr_email_clean, err = sanitize_email(manager_email)
        if err:
            return False, f"Manager email: {err}"
        if mgr_email_clean == email:
            return False, "Manager email must be different from your own email."

    # ── Uniqueness checks ──
    if username_exists(username):
        return False, "Username is already taken. Please choose another."
    if email_exists(email):
        return False, "An account with this email already exists."

    pw_hash = _hash_password(password.strip())

    import sqlite3, os
    from datetime import datetime

    DB_PATH = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "data", "vulndossier.db"
    )
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("""
            INSERT INTO users
                (username, email, password_hash, created_at, role,
                 account_type, manager_email, smtp_sender_email,
                 smtp_app_password, is_active, first_login)
            VALUES (?, ?, ?, ?, 'user', ?, ?, ?, ?, 1, 0)
        """, (
            username, email, pw_hash, datetime.now().isoformat(),
            account_type, mgr_email_clean,
            smtp_sender_email.strip(), smtp_app_password.strip()
        ))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return False, "Registration failed — duplicate entry. Please try again."
    conn.close()
    return True, "Account created successfully! You can now log in."


# ── Login ─────────────────────────────────────────────────────────────────────

def login(identifier: str, password: str) -> tuple:
    """
    Authenticate a user.
    Returns (success: bool, user_dict or error_str)
    Enforces brute-force protection and account active check.
    """
    identifier = identifier.strip()
    password   = password.strip()

    if not identifier or not password:
        return False, "Please enter both your username/email and password."

    # ── Sanitize identifier (light — just strip, allow email/username chars) ──
    if len(identifier) > 254:
        return False, "Invalid credentials."

    # ── Brute-force check ──
    allowed, msg, _ = check_login_allowed(identifier)
    if not allowed:
        return False, msg

    user = get_user_by_username_or_email(identifier)

    if not user or not verify_password(password, user.get("password_hash", "")):
        record_failed_login(identifier)
        record_login_attempt(identifier, False)
        remaining = _safe_remaining(identifier)
        if remaining <= 2 and remaining > 0:
            return False, f"Invalid credentials. {remaining} attempt(s) remaining before lockout."
        if remaining == 0:
            return False, "Too many failed attempts. Account temporarily locked for 15 minutes."
        return False, "Invalid username/email or password."

    # ── Account active check ──
    if not user.get("is_active", 1):
        record_login_attempt(identifier, False)
        return False, "Your account has been suspended. Please contact the administrator."

    # ── Success ──
    record_successful_login(identifier)
    record_login_attempt(identifier, True)
    update_last_login(user["id"])
    return True, user


def _safe_remaining(identifier: str) -> int:
    try:
        from utils.security import get_remaining_attempts
        return get_remaining_attempts(identifier)
    except Exception:
        return 3


# ── Admin Helpers ─────────────────────────────────────────────────────────────

def is_admin(user: dict) -> bool:
    return user.get("role", "user") == "admin"


def is_first_login(user: dict) -> bool:
    return bool(user.get("first_login", 0))


def is_company_account(user: dict) -> bool:
    return user.get("account_type", "personal") == "company"
