"""
security.py — Security utilities:
  • Password policy enforcement
  • Input sanitization (XSS / SQLi prevention)
  • Brute-force login protection (in-memory + DB-backed lockout)
  • CSRF token generation
  • Secure random token generation
"""
import re
import html
import time
import secrets
import string
from collections import defaultdict
from datetime import datetime, timedelta


# ── Password Policy ───────────────────────────────────────────────────────────

PASSWORD_MIN_LENGTH   = 8
PASSWORD_MAX_LENGTH   = 128
COMMON_PASSWORDS = {
    "password", "password1", "123456", "12345678", "qwerty",
    "abc123", "monkey", "1234567", "letmein", "trustno1",
    "dragon", "baseball", "iloveyou", "master", "sunshine",
    "ashley", "bailey", "passw0rd", "shadow", "123123",
    "654321", "superman", "michael", "football",     "admin123", "admin", "root", "toor", "pass", "test123",
}


def validate_password(password: str) -> tuple:
    """
    Enforce password policy.
    Returns (is_valid: bool, error_message: str)
    Policy:
      - Minimum 8 characters
      - Maximum 128 characters
      - At least 1 uppercase letter
      - At least 1 lowercase letter
      - At least 1 digit
      - At least 1 special character (!@#$%^&*...)
      - Not a commonly known weak password
    """
    if not password:
        return False, "Password cannot be empty."

    if len(password) < PASSWORD_MIN_LENGTH:
        return False, f"Password must be at least {PASSWORD_MIN_LENGTH} characters long."

    if len(password) > PASSWORD_MAX_LENGTH:
        return False, f"Password must not exceed {PASSWORD_MAX_LENGTH} characters."

    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter (A–Z)."

    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter (a–z)."

    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit (0–9)."

    if not re.search(r"[!@#$%^&*()\-_=+\[\]{};:'\",.<>?/\\|`~]", password):
        return False, "Password must contain at least one special character (!@#$%^&* etc.)."

    if password.lower() in COMMON_PASSWORDS:
        return False, "This password is too common. Please choose a stronger password."

    return True, ""


def password_strength_label(password: str) -> tuple:
    """
    Returns (strength: str, score: int 0-5, color_hint: str)
    for UI display purposes.
    """
    if not password:
        return "Empty", 0, "red"
    score = 0
    if len(password) >= 8:  score += 1
    if re.search(r"[A-Z]", password): score += 1
    if re.search(r"[a-z]", password): score += 1
    if re.search(r"\d", password):    score += 1
    if re.search(r"[!@#$%^&*()\-_=+\[\]{};:'\",.<>?/\\|`~]", password): score += 1
    if len(password) >= 14:           score = min(score + 1, 5)

    labels = {0: ("Very Weak", "red"), 1: ("Weak", "red"),
              2: ("Fair", "orange"), 3: ("Good", "orange"),
              4: ("Strong", "green"), 5: ("Very Strong", "green")}
    label, color = labels.get(score, ("Unknown", "gray"))
    return label, score, color


# ── Input Sanitization ────────────────────────────────────────────────────────

_DANGEROUS_SQL_PATTERNS = re.compile(
    r"(--|;|\/\*|\*\/|xp_|exec\s*\(|union\s+select|insert\s+into|drop\s+table"
    r"|delete\s+from|update\s+\w+\s+set|alter\s+table|create\s+table"
    r"|cast\s*\(|convert\s*\(|char\s*\(|nchar\s*\(|varchar\s*\()",
    re.IGNORECASE
)

_XSS_PATTERNS = re.compile(
    r"(<script|<\/script|javascript:|on\w+\s*=|<iframe|<object|<embed"
    r"|<link|<meta|data:text\/html|vbscript:|expression\s*\()",
    re.IGNORECASE
)

_PATH_TRAVERSAL = re.compile(r"\.\.[/\\]")


def sanitize_text(value: str, max_length: int = 500, field_name: str = "Field") -> tuple:
    """
    Sanitize a text input value.
    Returns (sanitized_value: str, error: str or None)
    - Strips leading/trailing whitespace
    - Escapes HTML special chars
    - Rejects known SQL injection patterns
    - Rejects XSS patterns
    - Enforces max length
    """
    if value is None:
        return "", None

    value = str(value).strip()

    if len(value) > max_length:
        return value[:max_length], f"{field_name} exceeds maximum length of {max_length} characters."

    if _DANGEROUS_SQL_PATTERNS.search(value):
        return "", f"{field_name} contains invalid characters or SQL keywords."

    if _XSS_PATTERNS.search(value):
        return "", f"{field_name} contains potentially unsafe HTML or script content."

    if _PATH_TRAVERSAL.search(value):
        return "", f"{field_name} contains invalid path characters."

    sanitized = html.escape(value, quote=True)
    return sanitized, None


def sanitize_email(email: str) -> tuple:
    """Validate and sanitize an email address."""
    if not email:
        return "", "Email cannot be empty."
    email = email.strip().lower()
    if len(email) > 254:
        return "", "Email address is too long."
    if not re.match(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", email):
        return "", "Invalid email address format."
    return email, None


def sanitize_username(username: str) -> tuple:
    """Validate and sanitize a username."""
    if not username:
        return "", "Username cannot be empty."
    username = username.strip()
    if len(username) < 3:
        return "", "Username must be at least 3 characters."
    if len(username) > 50:
        return "", "Username must not exceed 50 characters."
    if not re.match(r"^[a-zA-Z0-9_.\-]+$", username):
        return "", "Username can only contain letters, numbers, underscores, dots, and hyphens."
    return username, None


def sanitize_project_name(name: str) -> tuple:
    return sanitize_text(name, max_length=100, field_name="Project name")


def sanitize_scope(scope: str) -> tuple:
    """Scope can contain URLs and IPs — lighter validation."""
    if not scope:
        return "", "Scope cannot be empty."
    scope = scope.strip()
    if len(scope) > 2000:
        return scope[:2000], "Scope truncated to 2000 characters."
    if _XSS_PATTERNS.search(scope):
        return "", "Scope contains unsafe content."
    return scope, None


# ── Brute-Force Protection ────────────────────────────────────────────────────

# In-memory store: {identifier → {"attempts": int, "locked_until": float or None}}
_login_attempts: dict = defaultdict(lambda: {"attempts": 0, "locked_until": None})

MAX_ATTEMPTS       = 5      # lock after this many failures
LOCKOUT_SECONDS    = 900    # 15 minutes
ATTEMPT_WINDOW     = 600    # reset attempt count after 10 minutes of no failures


def check_login_allowed(identifier: str) -> tuple:
    """
    Check if a login attempt is allowed for an identifier (email/username).
    Returns (allowed: bool, message: str, remaining_seconds: int)
    """
    record = _login_attempts[identifier.lower()]
    now    = time.time()

    if record["locked_until"] and now < record["locked_until"]:
        remaining = int(record["locked_until"] - now)
        mins = remaining // 60
        secs = remaining % 60
        return False, f"Account temporarily locked. Try again in {mins}m {secs}s.", remaining

    if record["locked_until"] and now >= record["locked_until"]:
        _login_attempts[identifier.lower()] = {"attempts": 0, "locked_until": None}

    return True, "", 0


def record_failed_login(identifier: str):
    """Record a failed login attempt. Lock out if threshold exceeded."""
    record = _login_attempts[identifier.lower()]
    record["attempts"] += 1
    if record["attempts"] >= MAX_ATTEMPTS:
        record["locked_until"] = time.time() + LOCKOUT_SECONDS


def record_successful_login(identifier: str):
    """Clear failed attempts on successful login."""
    _login_attempts[identifier.lower()] = {"attempts": 0, "locked_until": None}


def get_remaining_attempts(identifier: str) -> int:
    """Return how many attempts remain before lockout."""
    record = _login_attempts.get(identifier.lower(), {"attempts": 0})
    return max(0, MAX_ATTEMPTS - record["attempts"])


# ── Secure Token Generation ───────────────────────────────────────────────────

def generate_auth_code(length: int = 8) -> str:
    """Generate a cryptographically secure uppercase alphanumeric auth code."""
    alphabet = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def generate_secure_token(length: int = 32) -> str:
    """Generate a secure hex token for CSRF or session use."""
    return secrets.token_hex(length)


def generate_temp_password(length: int = 12) -> str:
    """Generate a secure temporary password meeting policy requirements."""
    while True:
        chars = (
            secrets.choice(string.ascii_uppercase) +
            secrets.choice(string.ascii_lowercase) +
            secrets.choice(string.digits) +
            secrets.choice("!@#$%^&*") +
            ''.join(secrets.choice(
                string.ascii_letters + string.digits + "!@#$%^&*"
            ) for _ in range(length - 4))
        )
        shuffled = list(chars)
        secrets.SystemRandom().shuffle(shuffled)
        candidate = ''.join(shuffled)
        ok, _ = validate_password(candidate)
        if ok:
            return candidate
