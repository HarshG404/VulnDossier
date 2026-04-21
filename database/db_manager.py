"""
db_manager.py — SQLite database layer for VulnDossier v2.0
"""
import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "vulndossier.db")


def _get_conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def initialize_db():
    """Create all tables if they don't exist."""
    conn = _get_conn()
    c = conn.cursor()

    c.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        username      TEXT    UNIQUE NOT NULL,
        email         TEXT    UNIQUE NOT NULL,
        password_hash TEXT    NOT NULL,
        created_at    TEXT    NOT NULL
    );

    CREATE TABLE IF NOT EXISTS projects (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        project_name      TEXT NOT NULL,
        project_ref_id    TEXT,
        project_type      TEXT NOT NULL,
        start_date        TEXT NOT NULL,
        end_date          TEXT NOT NULL,
        criticality       TEXT NOT NULL,
        manager_email     TEXT NOT NULL,
        client_name       TEXT NOT NULL,
        scope             TEXT NOT NULL,
        pentester_name    TEXT NOT NULL,
        pentester_email   TEXT NOT NULL,
        classification    TEXT NOT NULL,
        reason            TEXT NOT NULL,
        walkthrough_done  TEXT NOT NULL,
        status            TEXT NOT NULL DEFAULT 'Request Pending',
        hold_reason       TEXT,
        executive_summary TEXT,
        auth_code         TEXT,
        review_notes      TEXT,
        created_by_email  TEXT NOT NULL,
        created_at        TEXT NOT NULL,
        updated_at        TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id          INTEGER NOT NULL,
        vuln_id             TEXT    NOT NULL,
        title               TEXT    NOT NULL,
        severity            TEXT    NOT NULL,
        cvss_score          REAL    NOT NULL,
        cvss_vector         TEXT,
        affected            TEXT    NOT NULL,
        description         TEXT    NOT NULL,
        impact              TEXT,
        recommendations     TEXT    NOT NULL,
        reference           TEXT,
        steps_to_reproduce  TEXT,
        found_at            TEXT    NOT NULL,
        FOREIGN KEY (project_id) REFERENCES projects(id)
    );

    CREATE TABLE IF NOT EXISTS removed_vulnerabilities (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id          INTEGER NOT NULL,
        original_vuln_id    TEXT    NOT NULL,
        title               TEXT    NOT NULL,
        severity            TEXT    NOT NULL,
        cvss_score          REAL    NOT NULL,
        cvss_vector         TEXT,
        affected            TEXT    NOT NULL,
        description         TEXT    NOT NULL,
        impact              TEXT,
        recommendations     TEXT    NOT NULL,
        reference           TEXT,
        steps_to_reproduce  TEXT,
        found_at            TEXT    NOT NULL,
        removed_at          TEXT    NOT NULL,
        removed_by          TEXT
    );

    CREATE TABLE IF NOT EXISTS admin_codes (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        code       TEXT UNIQUE NOT NULL,
        label      TEXT,
        created_at TEXT NOT NULL,
        is_active  INTEGER DEFAULT 1
    );
    """)

    # Seed a default admin code
    c.execute("SELECT COUNT(*) FROM admin_codes")
    if c.fetchone()[0] == 0:
        c.execute(
            "INSERT INTO admin_codes (code, label, created_at) VALUES (?, ?, ?)",
            ("ADMIN@2026", "Default admin code", datetime.now().isoformat())
        )

    conn.commit()
    conn.close()


# ── Users ──────────────────────────────────────────────────────────────────

def create_user(username: str, email: str, password_hash: str) -> bool:
    try:
        conn = _get_conn()
        conn.execute(
            "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (username, email.lower(), password_hash, datetime.now().isoformat())
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False


def get_user_by_email(email: str):
    conn = _get_conn()
    row = conn.execute(
        "SELECT * FROM users WHERE email = ?", (email.lower(),)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_username_or_email(identifier: str):
    conn = _get_conn()
    row = conn.execute(
        "SELECT * FROM users WHERE email = ? OR username = ?",
        (identifier.lower(), identifier)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def email_exists(email: str) -> bool:
    conn = _get_conn()
    row = conn.execute("SELECT id FROM users WHERE email = ?", (email.lower(),)).fetchone()
    conn.close()
    return row is not None


def username_exists(username: str) -> bool:
    conn = _get_conn()
    row = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return row is not None


def get_user_by_id(user_id: int):
    conn = _get_conn()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_users() -> list:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM users ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_user_role(user_id: int, role: str):
    conn = _get_conn()
    conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
    conn.commit()
    conn.close()


def set_user_active(user_id: int, is_active: bool):
    conn = _get_conn()
    conn.execute("UPDATE users SET is_active = ? WHERE id = ?", (1 if is_active else 0, user_id))
    conn.commit()
    conn.close()


def update_user_password(user_id: int, new_hash: str):
    conn = _get_conn()
    conn.execute(
        "UPDATE users SET password_hash = ?, first_login = 0 WHERE id = ?",
        (new_hash, user_id)
    )
    conn.commit()
    conn.close()


def record_login_attempt(identifier: str, success: bool):
    conn = _get_conn()
    conn.execute(
        "INSERT INTO login_audit (identifier, success, attempted_at) VALUES (?, ?, ?)",
        (identifier.lower(), 1 if success else 0, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()


def update_last_login(user_id: int):
    conn = _get_conn()
    conn.execute(
        "UPDATE users SET last_login = ? WHERE id = ?",
        (datetime.now().isoformat(), user_id)
    )
    conn.commit()
    conn.close()


def is_user_active(email: str) -> bool:
    conn = _get_conn()
    row = conn.execute(
        "SELECT is_active FROM users WHERE email = ?", (email.lower(),)
    ).fetchone()
    conn.close()
    return bool(row and row["is_active"])


def get_login_audit(limit: int = 50) -> list:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM login_audit ORDER BY attempted_at DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Projects ───────────────────────────────────────────────────────────────

def create_project(data: dict) -> int:
    now = datetime.now().isoformat()
    import secrets, string
    auth_code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
    conn = _get_conn()
    c = conn.cursor()
    c.execute("""
        INSERT INTO projects (
            project_name, project_ref_id, project_type, start_date, end_date,
            criticality, manager_email, client_name, scope,
            pentester_name, pentester_email, classification, reason,
            walkthrough_done, status, auth_code, created_by_email, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Request Pending', ?, ?, ?, ?)
    """, (
        data["project_name"], data.get("project_ref_id", ""),
        data["project_type"], data["start_date"], data["end_date"],
        data["criticality"], data["manager_email"], data["client_name"],
        data["scope"], data["pentester_name"], data["pentester_email"],
        data["classification"], data["reason"], data["walkthrough_done"],
        auth_code, data["created_by_email"], now, now
    ))
    project_id = c.lastrowid
    conn.commit()
    conn.close()
    return project_id, auth_code


def get_projects_by_user(email: str) -> list:
    """
    Returns projects where this user is the PENTESTER.
    Admin-raised projects for other users only show in that user's list.
    """
    conn = _get_conn()
    rows = conn.execute("""
        SELECT * FROM projects
        WHERE pentester_email = ?
           OR (created_by_email = ? AND (pentester_email = ? OR pentester_email IS NULL OR pentester_email = ''))
        ORDER BY created_at DESC
    """, (email, email, email)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_all_projects() -> list:
    conn = _get_conn()
    rows = conn.execute("SELECT * FROM projects ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_project_by_id(project_id: int):
    conn = _get_conn()
    row = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_project_by_name(name: str):
    conn = _get_conn()
    row = conn.execute(
        "SELECT * FROM projects WHERE LOWER(project_name) = LOWER(?)", (name,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def update_project_status(project_id: int, status: str, extra: dict = None):
    conn = _get_conn()
    now = datetime.now().isoformat()
    if extra:
        for key, val in extra.items():
            conn.execute(f"UPDATE projects SET {key} = ?, updated_at = ? WHERE id = ?",
                         (val, now, project_id))
    conn.execute("UPDATE projects SET status = ?, updated_at = ? WHERE id = ?",
                 (status, now, project_id))
    conn.commit()
    conn.close()


def update_project_field(project_id: int, field: str, value):
    conn = _get_conn()
    now = datetime.now().isoformat()
    conn.execute(f"UPDATE projects SET {field} = ?, updated_at = ? WHERE id = ?",
                 (value, now, project_id))
    conn.commit()
    conn.close()


def verify_auth_code(project_id: int, code: str) -> bool:
    conn = _get_conn()
    row = conn.execute(
        "SELECT auth_code FROM projects WHERE id = ?", (project_id,)
    ).fetchone()
    conn.close()
    return row and row["auth_code"] == code.upper().strip()


def verify_admin_code(code: str) -> bool:
    conn = _get_conn()
    row = conn.execute(
        "SELECT id FROM admin_codes WHERE code = ? AND is_active = 1", (code.upper().strip(),)
    ).fetchone()
    conn.close()
    return row is not None


def count_user_completed(email: str) -> int:
    conn = _get_conn()
    row = conn.execute("""
        SELECT COUNT(*) as cnt FROM projects
        WHERE (created_by_email = ? OR pentester_email = ?) AND status = 'Completed'
    """, (email, email)).fetchone()
    conn.close()
    return row["cnt"] if row else 0


# ── Vulnerabilities ────────────────────────────────────────────────────────

def get_next_vuln_id(project_id: int) -> str:
    """
    Generates next VUL-XXX ID by finding the highest number across
    active + removed vulnerabilities. Prevents duplicates after removals.
    """
    conn = _get_conn()
    # Max from active vulns
    row = conn.execute(
        "SELECT vuln_id FROM vulnerabilities WHERE project_id = ? ORDER BY id DESC LIMIT 1",
        (project_id,)
    ).fetchone()
    max_active = 0
    if row and row["vuln_id"]:
        try:
            max_active = int(row["vuln_id"].split("-")[1])
        except (IndexError, ValueError):
            max_active = 0

    # Max from removed vulns
    row2 = conn.execute(
        "SELECT original_vuln_id FROM removed_vulnerabilities WHERE project_id = ? ORDER BY id DESC LIMIT 1",
        (project_id,)
    ).fetchone()
    max_removed = 0
    if row2 and row2["original_vuln_id"]:
        try:
            max_removed = int(row2["original_vuln_id"].split("-")[1])
        except (IndexError, ValueError):
            max_removed = 0

    conn.close()
    return f"VUL-{max(max_active, max_removed) + 1:03d}"


def add_vulnerability(data: dict) -> int:
    conn = _get_conn()
    c = conn.cursor()
    c.execute("""
        INSERT INTO vulnerabilities (
            project_id, vuln_id, title, severity, cvss_score, cvss_vector,
            affected, description, impact, recommendations, reference,
            steps_to_reproduce, found_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data["project_id"], data["vuln_id"], data["title"],
        data["severity"], data["cvss_score"], data.get("cvss_vector", ""),
        data["affected"], data["description"], data.get("impact", ""),
        data["recommendations"], data.get("reference", "NA"),
        data.get("steps_to_reproduce", ""), datetime.now().isoformat()
    ))
    vid = c.lastrowid
    conn.commit()
    conn.close()
    return vid


def get_vulnerabilities(project_id: int) -> list:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM vulnerabilities WHERE project_id = ? ORDER BY id",
        (project_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_vulnerability_by_id(vuln_id: int):
    conn = _get_conn()
    row = conn.execute("SELECT * FROM vulnerabilities WHERE id = ?", (vuln_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def update_vulnerability(vuln_id: int, field: str, value):
    conn = _get_conn()
    conn.execute(f"UPDATE vulnerabilities SET {field} = ? WHERE id = ?", (value, vuln_id))
    conn.commit()
    conn.close()


def update_vulnerability_full(vuln_id: int, data: dict):
    conn = _get_conn()
    conn.execute("""
        UPDATE vulnerabilities SET
            title=?, severity=?, cvss_score=?, cvss_vector=?,
            affected=?, description=?, impact=?,
            recommendations=?, reference=?, steps_to_reproduce=?
        WHERE id=?
    """, (
        data["title"], data["severity"], data["cvss_score"], data.get("cvss_vector", ""),
        data["affected"], data["description"], data.get("impact", ""),
        data["recommendations"], data.get("reference", "NA"),
        data.get("steps_to_reproduce", ""), vuln_id
    ))
    conn.commit()
    conn.close()


def remove_vulnerability(vuln_db_id: int, removed_by: str):
    conn = _get_conn()
    row = conn.execute("SELECT * FROM vulnerabilities WHERE id = ?", (vuln_db_id,)).fetchone()
    if not row:
        conn.close()
        return False
    v = dict(row)
    conn.execute("""
        INSERT INTO removed_vulnerabilities (
            project_id, original_vuln_id, title, severity, cvss_score, cvss_vector,
            affected, description, impact, recommendations, reference,
            steps_to_reproduce, found_at, removed_at, removed_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        v["project_id"], v["vuln_id"], v["title"], v["severity"],
        v["cvss_score"], v.get("cvss_vector", ""), v["affected"],
        v["description"], v.get("impact", ""), v["recommendations"],
        v.get("reference", "NA"), v.get("steps_to_reproduce", ""),
        v["found_at"], datetime.now().isoformat(), removed_by
    ))
    conn.execute("DELETE FROM vulnerabilities WHERE id = ?", (vuln_db_id,))
    conn.commit()
    conn.close()
    return True


def get_removed_vulnerabilities(project_id: int) -> list:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM removed_vulnerabilities WHERE project_id = ? ORDER BY removed_at DESC",
        (project_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def save_removed_to_txt(project_id: int, project_name: str, client_name: str):
    """Save removed vulnerabilities to a text file."""
    removed = get_removed_vulnerabilities(project_id)
    if not removed:
        return
    safe_client = "".join(c if c.isalnum() else "_" for c in client_name)
    safe_project = "".join(c if c.isalnum() else "_" for c in project_name)
    folder = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "removed_vulnerabilities", safe_client, safe_project
    )
    os.makedirs(folder, exist_ok=True)
    filepath = os.path.join(folder, "removed_vulnerabilities.txt")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"REMOVED VULNERABILITIES\n")
        f.write(f"Project: {project_name} | Client: {client_name}\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")
        for v in removed:
            f.write(f"[{v['original_vuln_id']}] {v['title']}\n")
            f.write(f"  Severity      : {v['severity']} (CVSS {v['cvss_score']})\n")
            f.write(f"  Affected      : {v['affected']}\n")
            f.write(f"  Found At      : {v['found_at']}\n")
            f.write(f"  Removed At    : {v['removed_at']}\n")
            f.write(f"  Removed By    : {v.get('removed_by', 'N/A')}\n")
            f.write(f"  Description   : {v['description']}\n")
            f.write("-" * 40 + "\n\n")
    return filepath


def get_severity_counts(findings: list) -> dict:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for f in findings:
        sev = f.get("severity", "Low") if isinstance(f, dict) else "Low"
        if sev in counts:
            counts[sev] += 1
    return counts

def update_user_profile(user_id: int, username: str = None, email: str = None,
                        manager_email: str = None, smtp_sender_email: str = None,
                        smtp_app_password: str = None):
    """Update user profile fields. Only non-None values are updated."""
    conn = _get_conn()
    now = datetime.now().isoformat()
    if username:
        conn.execute("UPDATE users SET username=? WHERE id=?", (username, user_id))
    if email:
        conn.execute("UPDATE users SET email=? WHERE id=?", (email.lower(), user_id))
    if manager_email is not None:
        conn.execute("UPDATE users SET manager_email=? WHERE id=?", (manager_email, user_id))
    if smtp_sender_email is not None:
        conn.execute("UPDATE users SET smtp_sender_email=? WHERE id=?", (smtp_sender_email, user_id))
    if smtp_app_password is not None:
        conn.execute("UPDATE users SET smtp_app_password=? WHERE id=?", (smtp_app_password, user_id))
    conn.commit()
    conn.close()


def get_user_smtp_config(user_id: int) -> dict:
    """Get SMTP config for a specific user (company accounts)."""
    conn = _get_conn()
    row = conn.execute(
        "SELECT smtp_sender_email, smtp_app_password, manager_email FROM users WHERE id=?",
        (user_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else {}


def get_pending_requests() -> list:
    """Get all projects with 'Request Pending' status — for admin approval queue."""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM projects WHERE status='Request Pending' ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def approve_project_request(project_id: int):
    """Admin approves a raised request — moves to Waiting to start."""
    conn = _get_conn()
    now = datetime.now().isoformat()
    conn.execute(
        "UPDATE projects SET status='Waiting to start', updated_at=? WHERE id=?",
        (now, project_id)
    )
    conn.commit()
    conn.close()


def reject_project_request(project_id: int, reason: str = ""):
    """Admin rejects a raised request."""
    conn = _get_conn()
    now = datetime.now().isoformat()
    conn.execute(
        "UPDATE projects SET status='Rejected', hold_reason=?, updated_at=? WHERE id=?",
        (reason, now, project_id)
    )
    conn.commit()
    conn.close()


def update_vulnerability_status(vuln_id: int, status: str):
    """Mark vulnerability Open or Closed."""
    conn = _get_conn()
    conn.execute("UPDATE vulnerabilities SET vuln_status=? WHERE id=?", (status, vuln_id))
    conn.commit()
    conn.close()


def update_vulnerability_poc_images(vuln_id: int, images_json: str):
    """Save list of POC image paths as JSON string."""
    conn = _get_conn()
    conn.execute("UPDATE vulnerabilities SET poc_images=? WHERE id=?", (images_json, vuln_id))
    conn.commit()
    conn.close()


def get_admin_smtp_config() -> dict:
    """Get SMTP config from admin user account."""
    conn = _get_conn()
    row = conn.execute(
        "SELECT smtp_sender_email, smtp_app_password, email FROM users WHERE role='admin' ORDER BY id LIMIT 1"
    ).fetchone()
    conn.close()
    return dict(row) if row else {}



# ── OTP / Email Verification ──────────────────────────────────────────────────

def set_user_otp(user_id: int, otp_code: str, otp_type: str,
                  expires_at: str, pending_email: str = None):
    conn = _get_conn()
    conn.execute("""UPDATE users SET otp_code=?, otp_type=?, otp_expires=?,
                    pending_email=? WHERE id=?""",
                 (otp_code, otp_type, expires_at, pending_email, user_id))
    conn.commit(); conn.close()


def verify_user_otp(user_id: int, code: str, otp_type: str) -> bool:
    from datetime import datetime
    conn = _get_conn()
    row = conn.execute(
        "SELECT otp_code, otp_type, otp_expires, pending_email FROM users WHERE id=?",
        (user_id,)).fetchone()
    conn.close()
    if not row: return False
    if row["otp_code"] != code.strip().upper(): return False
    if row["otp_type"] != otp_type: return False
    if datetime.fromisoformat(row["otp_expires"]) < datetime.now(): return False
    return True


def confirm_email_verified(user_id: int, apply_pending: bool = False):
    conn = _get_conn()
    if apply_pending:
        row = conn.execute("SELECT pending_email FROM users WHERE id=?",
                           (user_id,)).fetchone()
        if row and row["pending_email"]:
            conn.execute("UPDATE users SET email=? WHERE id=?",
                         (row["pending_email"].lower(), user_id))
    conn.execute("""UPDATE users SET email_verified=1, otp_code=NULL,
                    otp_type=NULL, otp_expires=NULL, pending_email=NULL
                    WHERE id=?""", (user_id,))
    conn.commit(); conn.close()


def get_user_pending_email(user_id: int) -> str:
    conn = _get_conn()
    row = conn.execute("SELECT pending_email FROM users WHERE id=?",
                       (user_id,)).fetchone()
    conn.close()
    return row["pending_email"] if row else ""


# ── Project messages (deadline chat) ─────────────────────────────────────────

def add_project_message(project_id: int, sender_email: str,
                        sender_name: str, message: str,
                        message_type: str = "note") -> int:
    conn = _get_conn()
    c = conn.cursor()
    c.execute("""INSERT INTO project_messages
                 (project_id, sender_email, sender_name, message, message_type, created_at)
                 VALUES (?, ?, ?, ?, ?, ?)""",
              (project_id, sender_email, sender_name, message,
               message_type, datetime.now().isoformat()))
    mid = c.lastrowid
    conn.commit(); conn.close()
    return mid


def get_project_messages(project_id: int) -> list:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM project_messages WHERE project_id=? ORDER BY created_at",
        (project_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Project workflow additions ────────────────────────────────────────────────

def set_project_testing_started(project_id: int):
    conn = _get_conn()
    conn.execute("UPDATE projects SET testing_started=1, updated_at=? WHERE id=?",
                 (datetime.now().isoformat(), project_id))
    conn.commit(); conn.close()


def set_pre_start_requested(project_id: int, value: bool = True):
    conn = _get_conn()
    conn.execute("UPDATE projects SET pre_start_requested=? WHERE id=?",
                 (1 if value else 0, project_id))
    conn.commit(); conn.close()


def delete_project(project_id: int):
    """Delete a project and all its vulnerabilities (only if Request Pending)."""
    conn = _get_conn()
    conn.execute("DELETE FROM vulnerabilities WHERE project_id=?", (project_id,))
    conn.execute("DELETE FROM project_messages WHERE project_id=?", (project_id,))
    conn.execute("DELETE FROM projects WHERE id=?", (project_id,))
    conn.commit(); conn.close()


def update_project_full(project_id: int, data: dict):
    """Update editable project fields (for user editing own raised request)."""
    conn = _get_conn()
    now = datetime.now().isoformat()
    conn.execute("""UPDATE projects SET
        project_name=?, project_ref_id=?, project_type=?, start_date=?,
        end_date=?, criticality=?, client_name=?, scope=?, pentester_name=?,
        pentester_email=?, classification=?, reason=?, walkthrough_done=?,
        updated_at=? WHERE id=?""", (
        data["project_name"], data.get("project_ref_id",""),
        data["project_type"], data["start_date"], data["end_date"],
        data["criticality"], data["client_name"], data["scope"],
        data["pentester_name"], data["pentester_email"],
        data["classification"], data["reason"], data["walkthrough_done"],
        now, project_id))
    conn.commit(); conn.close()


def set_admin_review_note(project_id: int, note: str):
    conn = _get_conn()
    conn.execute("UPDATE projects SET admin_review_note=?, updated_at=? WHERE id=?",
                 (note, datetime.now().isoformat(), project_id))
    conn.commit(); conn.close()


def mark_report_emailed(project_id: int):
    conn = _get_conn()
    conn.execute("UPDATE projects SET report_emailed=1 WHERE id=?", (project_id,))
    conn.commit(); conn.close()



def get_admin_emails() -> list:
    """Get list of all admin email addresses."""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT email, username FROM users WHERE role='admin' AND is_active=1"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_projects_by_admin(admin_email: str) -> list:
    """Get projects assigned to a specific admin."""
    conn = _get_conn()
    rows = conn.execute(
        """SELECT * FROM projects WHERE assigned_admin_email=?
           ORDER BY created_at DESC""",
        (admin_email,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def set_password_reset_otp(user_id: int, otp: str, expires: str):
    conn = _get_conn()
    conn.execute(
        "UPDATE users SET password_reset_otp=?, password_reset_expires=? WHERE id=?",
        (otp, expires, user_id)
    )
    conn.commit(); conn.close()


def verify_password_reset_otp(identifier: str, otp: str) -> dict:
    """Verify reset OTP for email/username. Returns user dict or None."""
    from datetime import datetime
    conn = _get_conn()
    row = conn.execute(
        """SELECT * FROM users WHERE (email=? OR username=?)
           AND password_reset_otp=? AND is_active=1""",
        (identifier.lower(), identifier, otp.strip().upper())
    ).fetchone()
    if not row:
        conn.close(); return None
    user = dict(row)
    if user.get("password_reset_expires"):
        try:
            if datetime.fromisoformat(user["password_reset_expires"]) < datetime.now():
                conn.close(); return None
        except Exception:
            pass
    conn.execute(
        "UPDATE users SET password_reset_otp=NULL, password_reset_expires=NULL WHERE id=?",
        (user["id"],)
    )
    conn.commit(); conn.close()
    return user


def get_user_by_email_or_username(identifier: str):
    conn = _get_conn()
    row = conn.execute(
        "SELECT * FROM users WHERE email=? OR username=?",
        (identifier.lower(), identifier)
    ).fetchone()
    conn.close()
    return dict(row) if row else None



# ── Org Access / Permissions ──────────────────────────────────────────────────

def request_org_access(user_id: int, user_email: str, user_name: str,
                        admin_email: str, permission: str, note: str) -> int:
    conn = _get_conn()
    now = datetime.now().isoformat()
    c = conn.cursor()
    c.execute("""INSERT INTO org_access_requests
                 (user_id, user_email, user_name, admin_email, permission,
                  note, status, created_at, updated_at)
                 VALUES (?,?,?,?,?,?,'Pending',?,?)""",
              (user_id, user_email, user_name, admin_email, permission,
               note, now, now))
    rid = c.lastrowid
    conn.commit(); conn.close()
    return rid


def get_org_access_requests_for_admin(admin_email: str) -> list:
    conn = _get_conn()
    rows = conn.execute(
        """SELECT * FROM org_access_requests WHERE admin_email=?
           ORDER BY created_at DESC""",
        (admin_email,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_my_org_access_requests(user_id: int) -> list:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM org_access_requests WHERE user_id=? ORDER BY created_at DESC",
        (user_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def approve_org_access(request_id: int, admin_email: str,
                        permission: str, admin_note: str = ""):
    conn = _get_conn()
    now = datetime.now().isoformat()
    req = conn.execute("SELECT * FROM org_access_requests WHERE id=?",
                       (request_id,)).fetchone()
    if req:
        req = dict(req)
        # Upsert permission
        existing = conn.execute(
            "SELECT id FROM org_permissions WHERE user_id=?",
            (req["user_id"],)).fetchone()
        if existing:
            conn.execute(
                "UPDATE org_permissions SET permission=?, granted_by=?, granted_at=? WHERE user_id=?",
                (permission, admin_email, now, req["user_id"]))
        else:
            conn.execute(
                """INSERT INTO org_permissions
                   (user_id, user_email, permission, granted_by, granted_at)
                   VALUES (?,?,?,?,?)""",
                (req["user_id"], req["user_email"], permission, admin_email, now))
        conn.execute(
            "UPDATE org_access_requests SET status='Approved', admin_note=?, updated_at=? WHERE id=?",
            (admin_note, now, request_id))
    conn.commit(); conn.close()


def reject_org_access(request_id: int, admin_note: str = ""):
    conn = _get_conn()
    now = datetime.now().isoformat()
    conn.execute(
        "UPDATE org_access_requests SET status='Rejected', admin_note=?, updated_at=? WHERE id=?",
        (admin_note, now, request_id))
    conn.commit(); conn.close()


# get_user_org_permission replaced below


def renumber_vulnerabilities(project_id: int):
    """
    Renumber VUL IDs for a project in severity order (Critical first).
    Called after adding or removing a vulnerability.
    """
    conn = _get_conn()
    SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2,
                      "Low": 1, "Informational": 0}
    rows = conn.execute(
        "SELECT id, severity FROM vulnerabilities WHERE project_id=? ORDER BY id",
        (project_id,)).fetchall()
    # Sort by severity desc, then original id for stable sort
    sorted_rows = sorted(rows,
                         key=lambda r: (SEVERITY_ORDER.get(r["severity"], 0), -r["id"]),
                         reverse=True)
    for i, row in enumerate(sorted_rows, 1):
        conn.execute("UPDATE vulnerabilities SET vuln_id=? WHERE id=?",
                     (f"VUL-{i:03d}", row["id"]))
    conn.commit(); conn.close()



# ── Notifications ─────────────────────────────────────────────────────────────

def create_notification(user_email: str, title: str, message: str,
                         notif_type: str = "info",
                         link_type: str = "", link_id: int = 0):
    """Create a notification for a specific user by email."""
    conn = _get_conn()
    conn.execute("""INSERT INTO notifications
                    (user_email, title, message, notif_type, is_read,
                     link_type, link_id, created_at)
                    VALUES (?,?,?,?,0,?,?,?)""",
                 (user_email.lower(), title, message, notif_type,
                  link_type, link_id, datetime.now().isoformat()))
    conn.commit(); conn.close()


def get_notifications(user_email: str, unread_only: bool = False) -> list:
    conn = _get_conn()
    if unread_only:
        rows = conn.execute(
            """SELECT * FROM notifications WHERE user_email=? AND is_read=0
               ORDER BY created_at DESC""",
            (user_email.lower(),)).fetchall()
    else:
        rows = conn.execute(
            """SELECT * FROM notifications WHERE user_email=?
               ORDER BY created_at DESC LIMIT 50""",
            (user_email.lower(),)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def count_unread_notifications(user_email: str) -> int:
    conn = _get_conn()
    row = conn.execute(
        "SELECT COUNT(*) as cnt FROM notifications WHERE user_email=? AND is_read=0",
        (user_email.lower(),)).fetchone()
    conn.close()
    return row["cnt"] if row else 0


def mark_notification_read(notif_id: int):
    conn = _get_conn()
    conn.execute("UPDATE notifications SET is_read=1 WHERE id=?", (notif_id,))
    conn.commit(); conn.close()


def mark_all_notifications_read(user_email: str):
    conn = _get_conn()
    conn.execute("UPDATE notifications SET is_read=1 WHERE user_email=?",
                 (user_email.lower(),))
    conn.commit(); conn.close()


def broadcast_notification_to_admins(title: str, message: str,
                                      notif_type: str = "info",
                                      link_type: str = "", link_id: int = 0):
    """Send a notification to all active admin users."""
    conn = _get_conn()
    admins = conn.execute(
        "SELECT email FROM users WHERE role='admin' AND is_active=1"
    ).fetchall()
    now = datetime.now().isoformat()
    for a in admins:
        conn.execute("""INSERT INTO notifications
                        (user_email, title, message, notif_type, is_read,
                         link_type, link_id, created_at)
                        VALUES (?,?,?,?,0,?,?,?)""",
                     (a["email"], title, message, notif_type,
                      link_type, link_id, now))
    conn.commit(); conn.close()



def revoke_org_access(user_id: int):
    """Admin revokes org access for a user."""
    conn = _get_conn()
    now = datetime.now().isoformat()
    conn.execute(
        "UPDATE org_permissions SET is_active=0 WHERE user_id=?",
        (user_id,)
    )
    conn.execute(
        """UPDATE org_access_requests SET status='Revoked', updated_at=?
           WHERE user_id=? AND status='Approved'""",
        (now, user_id)
    )
    conn.commit()
    conn.close()


def set_org_access_expiry(user_id: int, expires_at: str):
    """Set expiry date on org permission."""
    conn = _get_conn()
    conn.execute(
        "UPDATE org_permissions SET expires_at=? WHERE user_id=?",
        (expires_at, user_id)
    )
    conn.commit()
    conn.close()


def get_all_org_permissions() -> list:
    """Get all org permissions (for admin management view)."""
    conn = _get_conn()
    rows = conn.execute(
        """SELECT op.*, u.username
           FROM org_permissions op
           LEFT JOIN users u ON op.user_id = u.id
           ORDER BY op.granted_at DESC"""
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_user_org_permission(user_id: int) -> str:
    """Returns active permission: 'read', 'write', or ''."""
    from datetime import datetime as _dt
    conn = _get_conn()
    row = conn.execute(
        """SELECT permission, expires_at, is_active
           FROM org_permissions WHERE user_id=? AND is_active=1""",
        (user_id,)
    ).fetchone()
    conn.close()
    if not row:
        return ""
    # Check expiry
    if row["expires_at"]:
        try:
            if _dt.fromisoformat(row["expires_at"]) < _dt.now():
                return ""  # expired
        except Exception:
            pass
    return row["permission"]

