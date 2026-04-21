"""
profile_window.py — User profile management.
  • Change username, email, password
  • Company users: update manager email and SMTP app password
  • Live password strength meter
  • All inputs sanitized
"""
import customtkinter as ctk
from tkinter import messagebox
from ui.theme import *
from auth.auth_manager import verify_password, hash_password_for_update, is_company_account
from utils.security import (
    validate_password, password_strength_label,
    sanitize_username, sanitize_email
)
from database.db_manager import (
    update_user_profile, update_user_password,
    username_exists, email_exists, get_user_by_id
)
from utils.email_sender import test_smtp_connection


class ProfileWindow(ctk.CTkToplevel):
    def __init__(self, parent, current_user: dict, on_profile_updated=None):
        super().__init__(parent)
        self.current_user      = current_user
        self.on_profile_updated = on_profile_updated
        self.title("My Profile")
        self.geometry("580x760")
        self.resizable(True, True)
        self.configure(fg_color=DARK_BG)
        self.grab_set()
        self._build()

    def _build(self):
        # Header
        hdr = ctk.CTkFrame(self, fg_color=PANEL_BG, corner_radius=0)
        hdr.pack(fill="x")
        ctk.CTkLabel(hdr, text="👤  My Profile",
                     font=FONT_HEADING, text_color=TEXT_PRIMARY).pack(
            side="left", padx=20, pady=14)
        ctk.CTkLabel(hdr, text=self.current_user.get("username", ""),
                     font=FONT_SMALL, text_color=ACCENT).pack(side="right", padx=20)

        scroll = ctk.CTkScrollableFrame(self, fg_color=DARK_BG)
        scroll.pack(fill="both", expand=True)

        # ── Account info ──────────────────────────────────────────────────────
        info_card = ctk.CTkFrame(scroll, fg_color=PANEL_BG, corner_radius=CARD_RADIUS)
        info_card.pack(fill="x", padx=20, pady=(16, 0))
        ctk.CTkLabel(info_card, text="Account Information",
                     font=FONT_SUBHEAD, text_color=ACCENT).pack(
            anchor="w", padx=16, pady=(12, 8))

        u = self.current_user
        for label, val in [
            ("Role",         u.get("role", "user").title()),
            ("Account Type", u.get("account_type", "personal").title()),
            ("Joined",       u.get("created_at", "")[:10]),
            ("Last Login",   (u.get("last_login") or "")[:16].replace("T", "  ")),
        ]:
            row = ctk.CTkFrame(info_card, fg_color="transparent")
            row.pack(fill="x", padx=16, pady=2)
            ctk.CTkLabel(row, text=f"{label}:", font=FONT_SMALL,
                         text_color=TEXT_MUTED, width=120, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=str(val), font=FONT_SMALL,
                         text_color=TEXT_PRIMARY, anchor="w").pack(side="left")
        ctk.CTkLabel(info_card, text="", height=6).pack()

        # ── Edit profile ──────────────────────────────────────────────────────
        edit_card = ctk.CTkFrame(scroll, fg_color=PANEL_BG, corner_radius=CARD_RADIUS)
        edit_card.pack(fill="x", padx=20, pady=(12, 0))
        ctk.CTkLabel(edit_card, text="Edit Profile",
                     font=FONT_SUBHEAD, text_color=ACCENT).pack(
            anchor="w", padx=16, pady=(12, 4))

        def lbl(text, required=True):
            ctk.CTkLabel(edit_card, text=f"{text}{' *' if required else ''}",
                         font=FONT_SMALL, text_color=TEXT_MUTED, anchor="w").pack(
                padx=16, pady=(8, 2), fill="x")

        def entry(val="", ph="", show=""):
            e = ctk.CTkEntry(edit_card, height=ENTRY_HEIGHT,
                             placeholder_text=ph, show=show,
                             fg_color=CARD_BG, border_color=BORDER,
                             text_color=TEXT_PRIMARY)
            e.pack(padx=16, fill="x")
            if val:
                e.insert(0, str(val))
            return e

        lbl("Username")
        self.e_username = entry(u.get("username", ""), "username")

        lbl("Email Address")
        self.e_email = entry(u.get("email", ""), "your@email.com")

        ctk.CTkLabel(edit_card, text="", height=4).pack()

        self.profile_err = ctk.CTkLabel(edit_card, text="", font=FONT_SMALL,
                                         text_color=SEV_COLORS["Critical"]["fg"],
                                         wraplength=480)
        self.profile_err.pack(padx=16, pady=(0, 4))

        ctk.CTkButton(edit_card, text="💾  Save Profile Changes",
                      height=BTN_HEIGHT, corner_radius=BTN_RADIUS,
                      fg_color=ACCENT, hover_color=ACCENT_HOVER,
                      font=FONT_BTN, command=self._save_profile).pack(
            padx=16, fill="x", pady=(0, 16))

        # ── Change password ───────────────────────────────────────────────────
        pw_card = ctk.CTkFrame(scroll, fg_color=PANEL_BG, corner_radius=CARD_RADIUS)
        pw_card.pack(fill="x", padx=20, pady=(12, 0))
        ctk.CTkLabel(pw_card, text="Change Password",
                     font=FONT_SUBHEAD, text_color=ACCENT).pack(
            anchor="w", padx=16, pady=(12, 4))

        def pw_lbl(text):
            ctk.CTkLabel(pw_card, text=text, font=FONT_SMALL,
                         text_color=TEXT_MUTED, anchor="w").pack(
                padx=16, pady=(8, 2), fill="x")

        def pw_entry(ph, show="•"):
            e = ctk.CTkEntry(pw_card, height=ENTRY_HEIGHT,
                             placeholder_text=ph, show=show,
                             fg_color=CARD_BG, border_color=BORDER,
                             text_color=TEXT_PRIMARY)
            e.pack(padx=16, fill="x")
            return e

        pw_lbl("Current Password *")
        self.e_cur_pw = pw_entry("Your current password")

        pw_lbl("New Password *")
        self.e_new_pw = pw_entry("Min 8 chars, upper, lower, digit, special char")
        self.e_new_pw.bind("<KeyRelease>", self._pw_strength)

        self.str_lbl = ctk.CTkLabel(pw_card, text="", font=("Segoe UI", 9),
                                     text_color=TEXT_MUTED)
        self.str_lbl.pack(padx=16, pady=(2, 0), anchor="w")
        self.str_bar = ctk.CTkProgressBar(pw_card, height=5)
        self.str_bar.pack(padx=16, fill="x", pady=(1, 4))
        self.str_bar.set(0)

        pw_lbl("Confirm New Password *")
        self.e_confirm_pw = pw_entry("Repeat new password")

        self.pw_err = ctk.CTkLabel(pw_card, text="", font=FONT_SMALL,
                                    text_color=SEV_COLORS["Critical"]["fg"],
                                    wraplength=480)
        self.pw_err.pack(padx=16, pady=(8, 4))

        ctk.CTkButton(pw_card, text="🔑  Update Password",
                      height=BTN_HEIGHT, corner_radius=BTN_RADIUS,
                      fg_color=ACCENT, hover_color=ACCENT_HOVER,
                      font=FONT_BTN, command=self._save_password).pack(
            padx=16, fill="x", pady=(0, 16))

        # ── Company email settings (company accounts only) ────────────────────
        if is_company_account(u):
            em_card = ctk.CTkFrame(scroll, fg_color=PANEL_BG, corner_radius=CARD_RADIUS)
            em_card.pack(fill="x", padx=20, pady=(12, 0))
            ctk.CTkLabel(em_card, text="Email / SMTP Settings",
                         font=FONT_SUBHEAD, text_color=ACCENT).pack(
                anchor="w", padx=16, pady=(12, 4))

            info = ctk.CTkFrame(em_card, fg_color=SEV_COLORS["Informational"]["bg"],
                                corner_radius=8)
            info.pack(fill="x", padx=16, pady=(0, 8))
            ctk.CTkLabel(info,
                         text="These settings are used to send auth code emails to your manager.\n"
                              "For Gmail: generate an App Password at myaccount.google.com/apppasswords",
                         font=FONT_SMALL, text_color=SEV_COLORS["Informational"]["fg"],
                         justify="left", wraplength=500).pack(padx=12, pady=8, anchor="w")

            def em_lbl(text):
                ctk.CTkLabel(em_card, text=text, font=FONT_SMALL,
                             text_color=TEXT_MUTED, anchor="w").pack(
                    padx=16, pady=(8, 2), fill="x")

            em_lbl("Manager Email Address *")
            self.e_mgr = ctk.CTkEntry(em_card, height=ENTRY_HEIGHT,
                                       placeholder_text="manager@company.com",
                                       fg_color=CARD_BG, border_color=BORDER,
                                       text_color=TEXT_PRIMARY)
            self.e_mgr.pack(padx=16, fill="x")
            if u.get("manager_email"):
                self.e_mgr.insert(0, u["manager_email"])

            em_lbl("Your Sender Email (Gmail/Outlook)")
            self.e_smtp_email = ctk.CTkEntry(em_card, height=ENTRY_HEIGHT,
                                              placeholder_text="your_gmail@gmail.com",
                                              fg_color=CARD_BG, border_color=BORDER,
                                              text_color=TEXT_PRIMARY)
            self.e_smtp_email.pack(padx=16, fill="x")
            if u.get("smtp_sender_email"):
                self.e_smtp_email.insert(0, u["smtp_sender_email"])

            em_lbl("Gmail App Password")
            self.e_smtp_pw = ctk.CTkEntry(em_card, height=ENTRY_HEIGHT,
                                           placeholder_text="xxxx xxxx xxxx xxxx",
                                           show="•", fg_color=CARD_BG,
                                           border_color=BORDER, text_color=TEXT_PRIMARY)
            self.e_smtp_pw.pack(padx=16, fill="x")

            self.em_err = ctk.CTkLabel(em_card, text="", font=FONT_SMALL,
                                        text_color=SEV_COLORS["Critical"]["fg"],
                                        wraplength=480)
            self.em_err.pack(padx=16, pady=(8, 4))

            btn_row = ctk.CTkFrame(em_card, fg_color="transparent")
            btn_row.pack(padx=16, fill="x", pady=(0, 16))
            ctk.CTkButton(btn_row, text="💾  Save Email Settings",
                          height=BTN_HEIGHT, corner_radius=BTN_RADIUS,
                          fg_color=ACCENT, hover_color=ACCENT_HOVER,
                          font=FONT_BTN, command=self._save_email_settings).pack(
                side="left", fill="x", expand=True, padx=(0, 8))
            ctk.CTkButton(btn_row, text="🔌  Test",
                          height=BTN_HEIGHT, width=80, corner_radius=BTN_RADIUS,
                          fg_color=CARD_BG, hover_color=BORDER,
                          text_color=TEXT_PRIMARY, font=FONT_BODY,
                          command=self._test_email).pack(side="left")

        # Bottom close button
        ctk.CTkButton(scroll, text="Close", height=BTN_HEIGHT,
                      corner_radius=BTN_RADIUS, fg_color="transparent",
                      border_color=BORDER, border_width=1,
                      text_color=TEXT_MUTED, hover_color=CARD_BG,
                      font=FONT_BODY, command=self.destroy).pack(
            padx=20, pady=16, fill="x")

    # ── Handlers ──────────────────────────────────────────────────────────────

    def _pw_strength(self, event=None):
        pw = self.e_new_pw.get()
        if not pw:
            self.str_lbl.configure(text="")
            self.str_bar.set(0)
            return
        label, score, color_hint = password_strength_label(pw)
        c_map = {"red": SEV_COLORS["Critical"]["fg"],
                 "orange": SEV_COLORS["Medium"]["fg"],
                 "green":  SEV_COLORS["Low"]["fg"]}
        self.str_lbl.configure(text=f"Strength: {label}",
                               text_color=c_map.get(color_hint, TEXT_MUTED))
        self.str_bar.set(score / 5)

    def _save_profile(self):
        new_username = self.e_username.get().strip()
        new_email    = self.e_email.get().strip()

        uname, err = sanitize_username(new_username)
        if err:
            self.profile_err.configure(text=err); return

        email, err = sanitize_email(new_email)
        if err:
            self.profile_err.configure(text=err); return

        uid = self.current_user["id"]

        if uname != self.current_user.get("username"):
            if username_exists(uname):
                self.profile_err.configure(text="Username already taken."); return

        email_changed = email != self.current_user.get("email","")
        if email_changed:
            if email_exists(email):
                self.profile_err.configure(text="Email already in use."); return
            # Trigger OTP for email change (skip for admin on first change)
            from utils.otp_manager import create_and_send_otp
            from utils.email_sender import is_email_configured
            if is_email_configured():
                ok, msg, _ = create_and_send_otp(uid, email, "email_change",
                                                  self.current_user.get("username",""),
                                                  pending_email=email)
                if ok:
                    # Store username change too, apply after OTP
                    from database.db_manager import update_user_profile as _up
                    _up(uid, username=uname)
                    self.current_user["username"] = uname
                    self.profile_err.configure(
                        text=f"✅ Username saved. OTP sent to {email} to confirm email change.",
                        text_color=ACCENT)
                    self._show_email_otp_field(uid, email, uname)
                    return
                else:
                    self.profile_err.configure(
                        text=f"⚠️ Could not send OTP: {msg}. Email not changed.",
                        text_color=SEV_COLORS["Medium"]["fg"])
                    # Still save username
                    from database.db_manager import update_user_profile as _up2
                    _up2(uid, username=uname)
                    self.current_user["username"] = uname
                    return
            else:
                # SMTP not configured — apply directly
                pass

        from database.db_manager import update_user_profile as _up3
        _up3(uid, username=uname, email=email if email_changed else None)
        self.current_user["username"] = uname
        if email_changed:
            self.current_user["email"] = email

        self.profile_err.configure(text="✅  Profile updated!", text_color=ACCENT)
        if self.on_profile_updated:
            self.on_profile_updated(self.current_user)

    def _show_email_otp_field(self, user_id, new_email, username):
        """Show inline OTP entry for email change."""
        from database.db_manager import verify_user_otp, confirm_email_verified
        otp_frame = ctk.CTkFrame(self, fg_color=SEV_COLORS["Informational"]["bg"],
                                  corner_radius=CARD_RADIUS)
        otp_frame.pack(padx=20, pady=8, fill="x")
        ctk.CTkLabel(otp_frame,
                     text=f"Enter the 6-character code sent to {new_email}:",
                     font=FONT_SMALL,
                     text_color=SEV_COLORS["Informational"]["fg"]).pack(
            padx=14, pady=(10,4), anchor="w")
        otp_entry = ctk.CTkEntry(otp_frame, height=ENTRY_HEIGHT,
                                  placeholder_text="Verification code",
                                  fg_color=CARD_BG, border_color=BORDER,
                                  text_color=TEXT_PRIMARY, font=FONT_MONO)
        otp_entry.pack(padx=14, fill="x")
        err2 = ctk.CTkLabel(otp_frame, text="", font=FONT_SMALL,
                             text_color=SEV_COLORS["Critical"]["fg"])
        err2.pack(padx=14, pady=(4,2))
        def verify():
            code = otp_entry.get().strip().upper()
            if verify_user_otp(user_id, code, "email_change"):
                confirm_email_verified(user_id, apply_pending=True)
                self.current_user["email"] = new_email
                otp_frame.destroy()
                self.profile_err.configure(text="✅  Email updated and verified!", text_color=ACCENT)
                if self.on_profile_updated:
                    self.on_profile_updated(self.current_user)
            else:
                err2.configure(text="Invalid or expired code.")
        ctk.CTkButton(otp_frame, text="Verify Email Change",
                      height=BTN_HEIGHT-4, corner_radius=BTN_RADIUS,
                      fg_color=ACCENT, hover_color=ACCENT_HOVER,
                      font=FONT_BTN, command=verify).pack(
            padx=14, fill="x", pady=(0,10))

    def _save_password(self):
        cur    = self.e_cur_pw.get().strip()
        new_pw = self.e_new_pw.get().strip()
        conf   = self.e_confirm_pw.get().strip()

        if not verify_password(cur, self.current_user.get("password_hash", "")):
            self.pw_err.configure(text="Current password is incorrect.")
            return

        ok, err = validate_password(new_pw)
        if not ok:
            self.pw_err.configure(text=err)
            return

        if new_pw != conf:
            self.pw_err.configure(text="Passwords do not match.")
            return

        new_hash = hash_password_for_update(new_pw)
        update_user_password(self.current_user["id"], new_hash)
        self.current_user["password_hash"] = new_hash

        self.e_cur_pw.delete(0, "end")
        self.e_new_pw.delete(0, "end")
        self.e_confirm_pw.delete(0, "end")
        self.str_bar.set(0)
        self.str_lbl.configure(text="")

        self.pw_err.configure(
            text="✅  Password updated successfully!", text_color=ACCENT)
        messagebox.showinfo("Password Updated",
            "Your password has been changed successfully.", parent=self)

    def _save_email_settings(self):
        mgr_email  = self.e_mgr.get().strip()
        smtp_email = self.e_smtp_email.get().strip()
        smtp_pw    = self.e_smtp_pw.get().strip()

        mgr_clean, err = sanitize_email(mgr_email) if mgr_email else ("", None)
        if err:
            self.em_err.configure(text=f"Manager email: {err}")
            return

        smtp_clean, err = sanitize_email(smtp_email) if smtp_email else ("", None)
        if err:
            self.em_err.configure(text=f"Sender email: {err}")
            return

        update_user_profile(
            self.current_user["id"],
            manager_email=mgr_clean,
            smtp_sender_email=smtp_clean,
            smtp_app_password=smtp_pw if smtp_pw else None,
        )
        self.current_user["manager_email"]    = mgr_clean
        self.current_user["smtp_sender_email"] = smtp_clean

        self.em_err.configure(
            text="✅  Email settings saved!", text_color=ACCENT)

    def _test_email(self):
        smtp_email = self.e_smtp_email.get().strip()
        smtp_pw    = self.e_smtp_pw.get().strip()

        if not smtp_email or not smtp_pw:
            self.em_err.configure(text="Enter sender email and app password first.")
            return

        self.em_err.configure(text="Testing connection...", text_color=TEXT_MUTED)
        self.update()

        cfg = {
            "smtp_host":      "smtp.gmail.com",
            "smtp_port":      587,
            "use_tls":        True,
            "sender_email":   smtp_email,
            "sender_password": smtp_pw,
        }
        ok, msg = test_smtp_connection(cfg)
        color = ACCENT if ok else SEV_COLORS["Critical"]["fg"]
        self.em_err.configure(text=f"{'✅' if ok else '❌'}  {msg}", text_color=color)
