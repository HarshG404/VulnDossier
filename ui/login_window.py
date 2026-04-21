"""
login_window.py — VulnDossier Login & Register.
  • Only Personal accounts (no company/team option)
  • OTP email verification on registration
  • OTP sent from admin's SMTP
"""
import customtkinter as ctk
from ui.theme import *
from auth.auth_manager import login, register, generate_captcha
from utils.security import password_strength_label
from database.db_manager import initialize_db, verify_user_otp, confirm_email_verified


class LoginWindow(ctk.CTk):
    def __init__(self, on_login_success):
        super().__init__()
        initialize_db()
        self._run_db_migration()
        self.on_login_success = on_login_success
        self._pending_user    = None   # user dict waiting for OTP confirm
        self.title("VulnDossier v2.1")
        self.geometry("500x560")
        self.resizable(False, False)
        ctk.set_appearance_mode(CTK_THEME)
        ctk.set_default_color_theme(CTK_COLOR)
        self.configure(fg_color=DARK_BG)
        self._build_login()

    # ── DB migration ──────────────────────────────────────────────────────────

    def _run_db_migration(self):
        import sqlite3, os, secrets, hashlib
        from datetime import datetime
        DB_PATH = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "data", "vulndossier.db"
        )
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row

        def col(table, col_name):
            return col_name in [r[1] for r in conn.execute(
                f"PRAGMA table_info({table})").fetchall()]

        for tbl, col_name, typedef in [
            ("users", "role",              "TEXT NOT NULL DEFAULT 'user'"),
            ("users", "account_type",      "TEXT NOT NULL DEFAULT 'personal'"),
            ("users", "manager_email",     "TEXT DEFAULT ''"),
            ("users", "smtp_sender_email", "TEXT DEFAULT ''"),
            ("users", "smtp_app_password", "TEXT DEFAULT ''"),
            ("users", "is_active",         "INTEGER NOT NULL DEFAULT 1"),
            ("users", "first_login",       "INTEGER NOT NULL DEFAULT 0"),
            ("users", "failed_attempts",   "INTEGER NOT NULL DEFAULT 0"),
            ("users", "locked_until",      "TEXT DEFAULT NULL"),
            ("users", "last_login",        "TEXT DEFAULT NULL"),
            ("users", "email_verified",    "INTEGER NOT NULL DEFAULT 0"),
            ("users", "otp_code",          "TEXT DEFAULT NULL"),
            ("users", "otp_expires",       "TEXT DEFAULT NULL"),
            ("users", "otp_type",          "TEXT DEFAULT NULL"),
            ("users", "pending_email",     "TEXT DEFAULT NULL"),
            ("projects", "pre_start_requested",  "INTEGER DEFAULT 0"),
            ("projects", "testing_started",      "INTEGER DEFAULT 0"),
            ("projects", "deadline_note",        "TEXT DEFAULT NULL"),
            ("projects", "admin_review_note",    "TEXT DEFAULT NULL"),
            ("projects", "report_emailed",       "INTEGER DEFAULT 0"),
            ("projects", "assigned_admin_email", "TEXT DEFAULT ''"),
            ("users",    "phone",                "TEXT DEFAULT ''"),
            ("users",    "password_reset_otp",      "TEXT DEFAULT NULL"),
            ("users",    "password_reset_expires",   "TEXT DEFAULT NULL"),
            ("vulnerabilities", "poc_images",   "TEXT DEFAULT '[]'"),
            ("vulnerabilities", "vuln_status",  "TEXT DEFAULT 'Open'"),

        ]:
            if not col(tbl, col_name):
                conn.execute(f"ALTER TABLE {tbl} ADD COLUMN {col_name} {typedef}")

        conn.executescript("""
            CREATE TABLE IF NOT EXISTS login_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                identifier TEXT NOT NULL,
                success INTEGER NOT NULL,
                ip_hint TEXT DEFAULT 'localhost',
                attempted_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS user_access (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                granted_by INTEGER NOT NULL,
                access_level TEXT NOT NULL DEFAULT 'user',
                granted_at TEXT NOT NULL,
                revoked_at TEXT DEFAULT NULL,
                is_active INTEGER DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS project_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                sender_email TEXT NOT NULL,
                sender_name TEXT NOT NULL,
                message TEXT NOT NULL,
                message_type TEXT DEFAULT 'note',
                created_at TEXT NOT NULL,
                FOREIGN KEY (project_id) REFERENCES projects(id)
            );
            CREATE TABLE IF NOT EXISTS org_access_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                user_email TEXT NOT NULL,
                user_name TEXT NOT NULL,
                admin_email TEXT NOT NULL,
                permission TEXT NOT NULL DEFAULT 'read',
                note TEXT DEFAULT '',
                status TEXT NOT NULL DEFAULT 'Pending',
                admin_note TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS org_permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                user_email TEXT NOT NULL,
                permission TEXT NOT NULL DEFAULT 'read',
                granted_by TEXT NOT NULL,
                granted_at TEXT NOT NULL,
                expires_at TEXT DEFAULT NULL,
                is_active INTEGER DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                notif_type TEXT DEFAULT 'info',
                is_read INTEGER DEFAULT 0,
                link_type TEXT DEFAULT '',
                link_id INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            );
        """)

        # Safely add new columns to org_permissions for older DBs
        for _col, _typedef in [
            ("expires_at", "TEXT DEFAULT NULL"),
            ("is_active",  "INTEGER DEFAULT 1"),
        ]:
            if _col not in [r[1] for r in conn.execute(
                    "PRAGMA table_info(org_permissions)").fetchall()]:
                conn.execute(f"ALTER TABLE org_permissions ADD COLUMN {_col} {_typedef}")

        # Mark all existing users as verified
        conn.execute("UPDATE users SET email_verified=1 WHERE email_verified IS NULL OR email_verified=0")

        # Seed admin
        if not conn.execute("SELECT id FROM users WHERE username='administrator'").fetchone():
            salt    = secrets.token_hex(16)
            h       = hashlib.sha256((salt + "Pa$$w0rd").encode()).hexdigest()
            conn.execute("""
                INSERT INTO users
                    (username, email, password_hash, created_at, role,
                     account_type, first_login, is_active, email_verified)
                VALUES ('administrator','admin@vulndossier.local',?,?,'admin','personal',0,1,1)
            """, (f"{salt}:{h}", datetime.now().isoformat()))

        conn.commit()
        conn.close()

    # ── Login ─────────────────────────────────────────────────────────────────

    def _build_login(self):
        self._clear()
        self.geometry("500x560")
        self.resizable(False, False)

        ctk.CTkLabel(self, text="🗂️", font=("Segoe UI", 44)).pack(pady=(32, 4))
        ctk.CTkLabel(self, text="VulnDossier",
                     font=FONT_TITLE, text_color=TEXT_PRIMARY).pack()
        ctk.CTkLabel(self, text="Penetration Test Management  •  v2.1",
                     font=FONT_SMALL, text_color=ACCENT).pack(pady=(2, 22))

        frame = ctk.CTkFrame(self, fg_color=PANEL_BG, corner_radius=CARD_RADIUS)
        frame.pack(padx=40, fill="x")

        ctk.CTkLabel(frame, text="Username or Email", font=FONT_SMALL,
                     text_color=TEXT_MUTED, anchor="w").pack(
            padx=16, pady=(14, 2), fill="x")
        self.login_id = ctk.CTkEntry(frame, height=ENTRY_HEIGHT,
                                     placeholder_text="username or email",
                                     fg_color=CARD_BG, border_color=BORDER,
                                     text_color=TEXT_PRIMARY)
        self.login_id.pack(padx=16, fill="x")

        ctk.CTkLabel(frame, text="Password", font=FONT_SMALL,
                     text_color=TEXT_MUTED, anchor="w").pack(
            padx=16, pady=(10, 2), fill="x")
        self.login_pw = ctk.CTkEntry(frame, height=ENTRY_HEIGHT,
                                     placeholder_text="password", show="•",
                                     fg_color=CARD_BG, border_color=BORDER,
                                     text_color=TEXT_PRIMARY)
        self.login_pw.pack(padx=16, fill="x")

        self.login_err = ctk.CTkLabel(frame, text="", font=FONT_SMALL,
                                      text_color=SEV_COLORS["Critical"]["fg"],
                                      wraplength=380)
        self.login_err.pack(padx=16, pady=(8, 2))

        ctk.CTkButton(frame, text="Sign In", height=BTN_HEIGHT + 2,
                      corner_radius=BTN_RADIUS, fg_color=ACCENT,
                      hover_color=ACCENT_HOVER, font=FONT_BTN,
                      command=self._do_login).pack(
            padx=16, fill="x", pady=(0, 16))

        ctk.CTkButton(self, text="Forgot Password?",
                      height=28, corner_radius=BTN_RADIUS,
                      fg_color="transparent",
                      text_color=TEXT_MUTED, hover_color=CARD_BG,
                      font=FONT_SMALL, command=self._build_forgot_password).pack(
            padx=40, pady=(10, 0))

        ctk.CTkLabel(self, text="Don't have an account?",
                     font=FONT_SMALL, text_color=TEXT_MUTED).pack(pady=(10, 4))
        ctk.CTkButton(self, text="Create Account",
                      height=BTN_HEIGHT - 2, corner_radius=BTN_RADIUS,
                      fg_color="transparent", border_color=ACCENT, border_width=1,
                      text_color=ACCENT, hover_color=CARD_BG,
                      font=FONT_BTN, command=self._build_register).pack(
            padx=40, fill="x")

        self.login_pw.bind("<Return>", lambda e: self._do_login())
        self.login_id.bind("<Return>", lambda e: self._do_login())

    def _do_login(self):
        ok, result = login(
            self.login_id.get().strip(),
            self.login_pw.get().strip()
        )
        if ok:
            user = result
            # Check email verified
            if not user.get("email_verified", 1):
                self._pending_user = user
                self._build_otp_verify(user["email"], "registration",
                                       user["id"], user["username"])
                return
            self.withdraw()
            self.on_login_success(user, self)
        else:
            self.login_err.configure(text=result)

    # ── Register ──────────────────────────────────────────────────────────────

    def _build_register(self):
        self._clear()
        self.geometry("500x700")
        self.resizable(False, True)

        ctk.CTkLabel(self, text="Create Account",
                     font=FONT_TITLE, text_color=TEXT_PRIMARY).pack(pady=(22, 2))
        ctk.CTkLabel(self, text="VulnDossier — Sign up for free",
                     font=FONT_SMALL, text_color=TEXT_MUTED).pack(pady=(0, 14))

        frame = ctk.CTkFrame(self, fg_color=PANEL_BG, corner_radius=CARD_RADIUS)
        frame.pack(padx=36, fill="x")

        def lbl(text, req=True):
            ctk.CTkLabel(frame, text=f"{text}{' *' if req else ''}",
                         font=FONT_SMALL, text_color=TEXT_MUTED, anchor="w").pack(
                padx=16, pady=(10, 2), fill="x")

        def ent(ph="", show=""):
            e = ctk.CTkEntry(frame, height=ENTRY_HEIGHT, placeholder_text=ph,
                             show=show, fg_color=CARD_BG, border_color=BORDER,
                             text_color=TEXT_PRIMARY)
            e.pack(padx=16, fill="x")
            return e

        lbl("Username")
        self.r_user = ent("Choose a username")

        lbl("Email Address")
        self.r_email = ent("your@email.com")

        lbl("Password")
        self.r_pw = ent("Min 8 chars, upper, lower, digit, special char", show="•")
        self.r_pw.bind("<KeyRelease>", self._pw_strength)

        self.str_lbl = ctk.CTkLabel(frame, text="", font=("Segoe UI", 9),
                                     text_color=TEXT_MUTED)
        self.str_lbl.pack(padx=16, pady=(2, 0), anchor="w")
        self.str_bar = ctk.CTkProgressBar(frame, height=5)
        self.str_bar.pack(padx=16, fill="x", pady=(1, 0))
        self.str_bar.set(0)

        lbl("Confirm Password")
        self.r_pw2 = ent("Repeat your password", show="•")

        # Captcha
        self.captcha_q, self.captcha_ans = generate_captcha()
        ctk.CTkLabel(frame,
                     text=f"Security Check: What is  {self.captcha_q}  ?",
                     font=FONT_BODY, text_color=ACCENT, anchor="w").pack(
            padx=16, pady=(12, 2), fill="x")
        self.r_cap = ent("Enter the answer (number only)")

        self.reg_err = ctk.CTkLabel(frame, text="", font=FONT_SMALL,
                                    text_color=SEV_COLORS["Critical"]["fg"],
                                    wraplength=420)
        self.reg_err.pack(padx=16, pady=(8, 4))

        ctk.CTkButton(frame, text="Register & Verify Email",
                      height=BTN_HEIGHT + 2,
                      corner_radius=BTN_RADIUS, fg_color=ACCENT,
                      hover_color=ACCENT_HOVER, font=FONT_BTN,
                      command=self._do_register).pack(
            padx=16, fill="x", pady=(0, 16))

        ctk.CTkLabel(self,
                     text="A verification code will be sent to your email\nfrom the admin's email address.",
                     font=FONT_SMALL, text_color=TEXT_MUTED,
                     justify="center").pack(pady=(8, 4))

        ctk.CTkButton(self, text="← Back to Login",
                      height=BTN_HEIGHT - 2, corner_radius=BTN_RADIUS,
                      fg_color="transparent", text_color=TEXT_MUTED,
                      hover_color=CARD_BG, font=FONT_BODY,
                      command=self._build_login).pack(padx=36, pady=8, fill="x")

    def _pw_strength(self, event=None):
        pw = self.r_pw.get()
        if not pw:
            self.str_lbl.configure(text="")
            self.str_bar.set(0)
            return
        label, score, color_hint = password_strength_label(pw)
        c_map = {"red":    SEV_COLORS["Critical"]["fg"],
                 "orange": SEV_COLORS["Medium"]["fg"],
                 "green":  SEV_COLORS["Low"]["fg"]}
        self.str_lbl.configure(
            text=f"Strength: {label}",
            text_color=c_map.get(color_hint, TEXT_MUTED))
        self.str_bar.set(score / 5)

    def _do_register(self):
        try:
            if int(self.r_cap.get().strip()) != self.captcha_ans:
                self.reg_err.configure(text="Security check answer is incorrect.")
                return
        except ValueError:
            self.reg_err.configure(text="Security check must be a number.")
            return

        ok, msg = register(
            username         = self.r_user.get(),
            email            = self.r_email.get(),
            password         = self.r_pw.get(),
            confirm_password = self.r_pw2.get(),
            account_type     = "personal",
        )
        if not ok:
            self.reg_err.configure(text=msg,
                                   text_color=SEV_COLORS["Critical"]["fg"])
            return

        # Registration succeeded → need OTP
        from auth.auth_manager import login as do_login
        ok2, user = do_login(self.r_user.get(), self.r_pw.get())
        if ok2:
            self._pending_user = user
            self._build_otp_verify(user["email"], "registration",
                                   user["id"], user["username"],
                                   send_now=True)
        else:
            self.reg_err.configure(text="Account created. Please log in.",
                                   text_color=SEV_COLORS["Low"]["fg"])
            self.after(1500, self._build_login)

    # ── OTP Verification ──────────────────────────────────────────────────────

    def _build_otp_verify(self, email: str, otp_type: str,
                          user_id: int, username: str,
                          send_now: bool = False):
        """Show OTP entry screen."""
        self._clear()
        self.geometry("500x500")
        self.resizable(False, False)

        ctk.CTkLabel(self, text="📧", font=("Segoe UI", 44)).pack(pady=(32, 4))
        ctk.CTkLabel(self, text="Verify Your Email",
                     font=FONT_TITLE, text_color=TEXT_PRIMARY).pack()
        ctk.CTkLabel(self,
                     text=f"A 6-character code has been sent to\n{email}",
                     font=FONT_SMALL, text_color=TEXT_MUTED,
                     justify="center").pack(pady=(4, 20))

        frame = ctk.CTkFrame(self, fg_color=PANEL_BG, corner_radius=CARD_RADIUS)
        frame.pack(padx=40, fill="x")

        ctk.CTkLabel(frame, text="Verification Code *", font=FONT_SMALL,
                     text_color=TEXT_MUTED, anchor="w").pack(
            padx=16, pady=(14, 2), fill="x")
        self.otp_entry = ctk.CTkEntry(
            frame, height=ENTRY_HEIGHT + 10,
            placeholder_text="Enter 6-character code",
            fg_color=CARD_BG, border_color=BORDER,
            text_color=TEXT_PRIMARY,
            font=("Consolas", 18),
            justify="center"
        )
        self.otp_entry.pack(padx=16, fill="x")

        self.otp_err = ctk.CTkLabel(frame, text="", font=FONT_SMALL,
                                    text_color=SEV_COLORS["Critical"]["fg"],
                                    wraplength=380)
        self.otp_err.pack(padx=16, pady=(8, 4))

        ctk.CTkButton(frame, text="Verify & Continue",
                      height=BTN_HEIGHT + 2, corner_radius=BTN_RADIUS,
                      fg_color=ACCENT, hover_color=ACCENT_HOVER, font=FONT_BTN,
                      command=lambda: self._verify_otp(
                          user_id, otp_type, email)).pack(
            padx=16, fill="x", pady=(0, 8))

        ctk.CTkButton(frame, text="Resend Code", height=BTN_HEIGHT - 2,
                      corner_radius=BTN_RADIUS, fg_color="transparent",
                      border_color=BORDER, border_width=1,
                      text_color=TEXT_MUTED, hover_color=CARD_BG,
                      font=FONT_BODY,
                      command=lambda: self._resend_otp(
                          user_id, email, otp_type, username)).pack(
            padx=16, fill="x", pady=(0, 16))

        ctk.CTkButton(self, text="← Back to Login",
                      height=BTN_HEIGHT - 2, corner_radius=BTN_RADIUS,
                      fg_color="transparent", text_color=TEXT_MUTED,
                      hover_color=CARD_BG, font=FONT_BODY,
                      command=self._build_login).pack(padx=40, pady=10, fill="x")

        # Store for use in verify
        self._otp_user_id = user_id
        self._otp_email   = email
        self._otp_type    = otp_type
        self._otp_username = username

        if send_now:
            self._resend_otp(user_id, email, otp_type, username)

        self.otp_entry.bind("<Return>",
                            lambda e: self._verify_otp(user_id, otp_type, email))

    def _resend_otp(self, user_id, email, otp_type, username):
        from utils.otp_manager import create_and_send_otp
        from utils.email_sender import is_email_configured
        if not is_email_configured():
            # If SMTP not configured, auto-verify (dev mode)
            self.otp_err.configure(
                text="⚠️ Admin email not configured. Code sent to console only.\n"
                     "Type: DEVPASS to bypass (dev mode).",
                text_color=SEV_COLORS["Medium"]["fg"])
            from database.db_manager import set_user_otp
            from datetime import datetime, timedelta
            set_user_otp(user_id, "DEVPASS", otp_type,
                         (datetime.now() + timedelta(minutes=10)).isoformat())
            return

        ok, msg, _ = create_and_send_otp(user_id, email, otp_type, username)
        if ok:
            self.otp_err.configure(
                text=f"✅ Code sent to {email}", text_color=ACCENT)
        else:
            self.otp_err.configure(text=f"⚠️ {msg}",
                                   text_color=SEV_COLORS["Medium"]["fg"])

    def _verify_otp(self, user_id, otp_type, email):
        code = self.otp_entry.get().strip().upper()
        if not code:
            self.otp_err.configure(text="Please enter the verification code.")
            return

        ok = verify_user_otp(user_id, code, otp_type)
        if not ok:
            self.otp_err.configure(
                text="Invalid or expired code. Try again or click Resend.",
                text_color=SEV_COLORS["Critical"]["fg"])
            return

        confirm_email_verified(user_id, apply_pending=(otp_type == "email_change"))

        # Always go to login page after verification
        if otp_type == "registration":
            from tkinter import messagebox
            messagebox.showinfo("✅  Email Verified!",
                "Your email has been verified successfully!\n\n"
                "Please log in with your credentials.",
                parent=self)
        else:
            from tkinter import messagebox
            messagebox.showinfo("✅  Email Updated",
                "Your email has been verified and updated!", parent=self)
        self._build_login()

    # ── Forgot Password ───────────────────────────────────────────────────────

    def _build_forgot_password(self):
        """Step 1: Enter username or email."""
        self._clear()
        self.geometry("500x460")
        self.resizable(False, False)

        ctk.CTkLabel(self, text="🔒", font=("Segoe UI", 44)).pack(pady=(32, 4))
        ctk.CTkLabel(self, text="Reset Password",
                     font=FONT_TITLE, text_color=TEXT_PRIMARY).pack()
        ctk.CTkLabel(self,
                     text="Enter your username or email address.",
                     font=FONT_SMALL, text_color=TEXT_MUTED).pack(pady=(4, 20))

        frame = ctk.CTkFrame(self, fg_color=PANEL_BG, corner_radius=CARD_RADIUS)
        frame.pack(padx=40, fill="x")

        ctk.CTkLabel(frame, text="Username or Email *", font=FONT_SMALL,
                     text_color=TEXT_MUTED, anchor="w").pack(
            padx=16, pady=(14, 2), fill="x")
        self.fp_id = ctk.CTkEntry(frame, height=ENTRY_HEIGHT,
                                   placeholder_text="your_username or your@email.com",
                                   fg_color=CARD_BG, border_color=BORDER,
                                   text_color=TEXT_PRIMARY)
        self.fp_id.pack(padx=16, fill="x")

        self.fp_err = ctk.CTkLabel(frame, text="", font=FONT_SMALL,
                                    text_color=SEV_COLORS["Critical"]["fg"],
                                    wraplength=380)
        self.fp_err.pack(padx=16, pady=(8, 4))

        ctk.CTkButton(frame, text="Send Reset Code",
                      height=BTN_HEIGHT + 2, corner_radius=BTN_RADIUS,
                      fg_color=ACCENT, hover_color=ACCENT_HOVER, font=FONT_BTN,
                      command=self._send_reset_code).pack(
            padx=16, fill="x", pady=(0, 16))

        ctk.CTkButton(self, text="← Back to Login",
                      height=BTN_HEIGHT - 2, corner_radius=BTN_RADIUS,
                      fg_color="transparent", text_color=TEXT_MUTED,
                      hover_color=CARD_BG, font=FONT_BODY,
                      command=self._build_login).pack(padx=40, pady=10, fill="x")

        self.fp_id.bind("<Return>", lambda e: self._send_reset_code())

    def _send_reset_code(self):
        identifier = self.fp_id.get().strip()
        if not identifier:
            self.fp_err.configure(text="Please enter your username or email.")
            return

        from database.db_manager import get_user_by_email_or_username
        user = get_user_by_email_or_username(identifier)
        if not user:
            # Security: don't reveal if user exists
            self.fp_err.configure(
                text="If that username/email exists, a reset code has been sent.",
                text_color=TEXT_MUTED)
            return

        # Generate reset OTP
        from utils.otp_manager import generate_otp
        from database.db_manager import set_password_reset_otp
        from datetime import datetime, timedelta
        otp_code   = generate_otp()
        expires_at = (datetime.now() + timedelta(minutes=15)).isoformat()
        set_password_reset_otp(user["id"], otp_code, expires_at)

        # Send email
        from utils.email_sender import is_email_configured
        from utils.otp_manager import send_otp_email
        if is_email_configured():
            ok, msg = send_otp_email(
                user["email"], otp_code,
                "password reset", user["username"]
            )
            if ok:
                self.fp_err.configure(
                    text=f"✅  Reset code sent to {user['email']}",
                    text_color=ACCENT)
            else:
                self.fp_err.configure(
                    text=f"⚠️  Email failed: {msg}. Code: {otp_code} (dev mode)",
                    text_color=SEV_COLORS["Medium"]["fg"])
        else:
            # SMTP not configured — show code
            self.fp_err.configure(
                text=f"⚠️  SMTP not configured. Code (dev): {otp_code}",
                text_color=SEV_COLORS["Medium"]["fg"])

        self._build_reset_code_entry(user)

    def _build_reset_code_entry(self, user):
        """Step 2: Enter code and new password."""
        self._clear()
        self.geometry("500x560")
        self.resizable(False, True)

        ctk.CTkLabel(self, text="🔑", font=("Segoe UI", 44)).pack(pady=(28, 4))
        ctk.CTkLabel(self, text="Enter Reset Code",
                     font=FONT_TITLE, text_color=TEXT_PRIMARY).pack()
        ctk.CTkLabel(self,
                     text=f"Code sent to: {user['email']}",
                     font=FONT_SMALL, text_color=TEXT_MUTED).pack(pady=(4, 16))

        frame = ctk.CTkFrame(self, fg_color=PANEL_BG, corner_radius=CARD_RADIUS)
        frame.pack(padx=40, fill="x")

        ctk.CTkLabel(frame, text="6-Character Reset Code *", font=FONT_SMALL,
                     text_color=TEXT_MUTED, anchor="w").pack(
            padx=16, pady=(14, 2), fill="x")
        self.fp_code = ctk.CTkEntry(frame, height=ENTRY_HEIGHT + 8,
                                     placeholder_text="Enter code",
                                     fg_color=CARD_BG, border_color=BORDER,
                                     text_color=TEXT_PRIMARY,
                                     font=("Consolas", 18),
                                     justify="center")
        self.fp_code.pack(padx=16, fill="x")

        ctk.CTkLabel(frame, text="New Password *", font=FONT_SMALL,
                     text_color=TEXT_MUTED, anchor="w").pack(
            padx=16, pady=(12, 2), fill="x")
        self.fp_new_pw = ctk.CTkEntry(frame, height=ENTRY_HEIGHT,
                                       placeholder_text="New password",
                                       show="•", fg_color=CARD_BG,
                                       border_color=BORDER, text_color=TEXT_PRIMARY)
        self.fp_new_pw.pack(padx=16, fill="x")
        self.fp_new_pw.bind("<KeyRelease>", lambda e: self._fp_strength())

        self.fp_str_lbl = ctk.CTkLabel(frame, text="", font=("Segoe UI", 9),
                                        text_color=TEXT_MUTED)
        self.fp_str_lbl.pack(padx=16, pady=(2,0), anchor="w")
        self.fp_str_bar = ctk.CTkProgressBar(frame, height=5)
        self.fp_str_bar.pack(padx=16, fill="x", pady=(1,0))
        self.fp_str_bar.set(0)

        ctk.CTkLabel(frame, text="Confirm New Password *", font=FONT_SMALL,
                     text_color=TEXT_MUTED, anchor="w").pack(
            padx=16, pady=(12, 2), fill="x")
        self.fp_confirm = ctk.CTkEntry(frame, height=ENTRY_HEIGHT,
                                        placeholder_text="Confirm new password",
                                        show="•", fg_color=CARD_BG,
                                        border_color=BORDER, text_color=TEXT_PRIMARY)
        self.fp_confirm.pack(padx=16, fill="x")

        self.fp_err2 = ctk.CTkLabel(frame, text="", font=FONT_SMALL,
                                     text_color=SEV_COLORS["Critical"]["fg"],
                                     wraplength=380)
        self.fp_err2.pack(padx=16, pady=(8, 4))

        ctk.CTkButton(frame, text="Reset Password",
                      height=BTN_HEIGHT + 2, corner_radius=BTN_RADIUS,
                      fg_color=ACCENT, hover_color=ACCENT_HOVER, font=FONT_BTN,
                      command=lambda u=user: self._do_reset(u)).pack(
            padx=16, fill="x", pady=(0, 16))

        ctk.CTkButton(self, text="← Back to Login",
                      height=BTN_HEIGHT - 2, corner_radius=BTN_RADIUS,
                      fg_color="transparent", text_color=TEXT_MUTED,
                      hover_color=CARD_BG, font=FONT_BODY,
                      command=self._build_login).pack(padx=40, pady=8, fill="x")

        self._fp_reset_user = user

    def _fp_strength(self):
        from utils.security import password_strength_label
        pw = self.fp_new_pw.get()
        if not pw:
            self.fp_str_lbl.configure(text="")
            self.fp_str_bar.set(0)
            return
        label, score, ch = password_strength_label(pw)
        c_map = {"red": SEV_COLORS["Critical"]["fg"],
                 "orange": SEV_COLORS["Medium"]["fg"],
                 "green": SEV_COLORS["Low"]["fg"]}
        self.fp_str_lbl.configure(text=f"Strength: {label}",
                                   text_color=c_map.get(ch, TEXT_MUTED))
        self.fp_str_bar.set(score / 5)

    def _do_reset(self, user):
        code    = self.fp_code.get().strip().upper()
        new_pw  = self.fp_new_pw.get().strip()
        confirm = self.fp_confirm.get().strip()

        if not code:
            self.fp_err2.configure(text="Please enter the reset code.")
            return

        from database.db_manager import verify_password_reset_otp
        verified_user = verify_password_reset_otp(user["username"], code)
        if not verified_user:
            # Also try by email
            verified_user = verify_password_reset_otp(user["email"], code)
        if not verified_user:
            self.fp_err2.configure(text="Invalid or expired code. Try again.")
            return

        from utils.security import validate_password
        ok, err = validate_password(new_pw)
        if not ok:
            self.fp_err2.configure(text=err)
            return
        if new_pw != confirm:
            self.fp_err2.configure(text="Passwords do not match.")
            return

        from auth.auth_manager import hash_password_for_update
        from database.db_manager import update_user_password
        new_hash = hash_password_for_update(new_pw)
        update_user_password(verified_user["id"], new_hash)

        from tkinter import messagebox
        messagebox.showinfo("✅  Password Reset",
            "Your password has been reset successfully!\n\n"
            "Please log in with your new password.", parent=self)
        self._build_login()

    def _clear(self):
        for w in self.winfo_children():
            w.destroy()
