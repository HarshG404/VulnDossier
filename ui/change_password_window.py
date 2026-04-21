"""
change_password_window.py — Force password change on first admin login.
Also used for voluntary password changes.
"""
import customtkinter as ctk
from tkinter import messagebox
from ui.theme import *
from auth.auth_manager import hash_password_for_update, verify_password
from utils.security import validate_password, password_strength_label
from database.db_manager import update_user_password


class ChangePasswordWindow(ctk.CTkToplevel):
    def __init__(self, parent, user: dict, forced: bool = False, on_success=None):
        super().__init__(parent)
        self.user       = user
        self.forced     = forced
        self.on_success = on_success

        title = "Set New Password — Required on First Login" if forced else "Change Password"
        self.title(title)
        self.geometry("480x520")
        self.resizable(False, False)
        self.configure(fg_color=DARK_BG)
        self.grab_set()

        if forced:
            self.protocol("WM_DELETE_WINDOW", lambda: None)

        self._build()

    def _build(self):
        ctk.CTkLabel(self, text="🔑", font=("Segoe UI", 36)).pack(pady=(30, 4))

        if self.forced:
            ctk.CTkLabel(self, text="Set Your New Password",
                         font=FONT_HEADING, text_color=TEXT_PRIMARY).pack()
            ctk.CTkLabel(self,
                         text="For security, you must change the default password\nbefore accessing the admin panel.",
                         font=FONT_SMALL, text_color=TEXT_MUTED,
                         justify="center").pack(pady=(4, 20))
        else:
            ctk.CTkLabel(self, text="Change Password",
                         font=FONT_HEADING, text_color=TEXT_PRIMARY).pack(pady=(0, 20))

        card = ctk.CTkFrame(self, fg_color=PANEL_BG, corner_radius=CARD_RADIUS)
        card.pack(padx=30, fill="x")

        if not self.forced:
            ctk.CTkLabel(card, text="Current Password", font=FONT_SMALL,
                         text_color=TEXT_MUTED, anchor="w").pack(padx=16, pady=(14, 2), fill="x")
            self.e_current = ctk.CTkEntry(card, height=ENTRY_HEIGHT, show="•",
                                          fg_color=CARD_BG, border_color=BORDER,
                                          text_color=TEXT_PRIMARY)
            self.e_current.pack(padx=16, fill="x")
        else:
            self.e_current = None

        ctk.CTkLabel(card, text="New Password", font=FONT_SMALL,
                     text_color=TEXT_MUTED, anchor="w").pack(padx=16, pady=(12, 2), fill="x")
        self.e_new = ctk.CTkEntry(card, height=ENTRY_HEIGHT, show="•",
                                  fg_color=CARD_BG, border_color=BORDER,
                                  text_color=TEXT_PRIMARY)
        self.e_new.pack(padx=16, fill="x")
        self.e_new.bind("<KeyRelease>", self._update_strength)

        # Strength bar
        self.strength_lbl = ctk.CTkLabel(card, text="", font=FONT_SMALL,
                                          text_color=TEXT_MUTED)
        self.strength_lbl.pack(padx=16, pady=(4, 0), anchor="w")
        self.strength_bar = ctk.CTkProgressBar(card, height=6)
        self.strength_bar.pack(padx=16, fill="x", pady=(2, 0))
        self.strength_bar.set(0)

        # Policy hint
        ctk.CTkLabel(card,
                     text="Min 8 chars • Uppercase • Lowercase • Number • Special char",
                     font=("Segoe UI", 9), text_color=TEXT_MUTED).pack(
            padx=16, pady=(4, 0), anchor="w")

        ctk.CTkLabel(card, text="Confirm New Password", font=FONT_SMALL,
                     text_color=TEXT_MUTED, anchor="w").pack(padx=16, pady=(12, 2), fill="x")
        self.e_confirm = ctk.CTkEntry(card, height=ENTRY_HEIGHT, show="•",
                                      fg_color=CARD_BG, border_color=BORDER,
                                      text_color=TEXT_PRIMARY)
        self.e_confirm.pack(padx=16, fill="x", pady=(0, 16))

        self.err_lbl = ctk.CTkLabel(self, text="", font=FONT_SMALL,
                                    text_color=SEV_COLORS["Critical"]["fg"],
                                    wraplength=400)
        self.err_lbl.pack(pady=(10, 4))

        btn_text = "Set Password & Continue" if self.forced else "Update Password"
        ctk.CTkButton(self, text=btn_text, height=BTN_HEIGHT + 4,
                      corner_radius=BTN_RADIUS, fg_color=ACCENT, hover_color=ACCENT_HOVER,
                      font=FONT_BTN, command=self._submit).pack(padx=30, pady=(0, 8), fill="x")

        if not self.forced:
            ctk.CTkButton(self, text="Cancel", height=BTN_HEIGHT,
                          corner_radius=BTN_RADIUS, fg_color="transparent",
                          border_color=BORDER, border_width=1,
                          text_color=TEXT_MUTED, hover_color=CARD_BG,
                          font=FONT_BODY, command=self.destroy).pack(padx=30, fill="x")

    def _update_strength(self, event=None):
        pw = self.e_new.get()
        if not pw:
            self.strength_lbl.configure(text="")
            self.strength_bar.set(0)
            return
        label, score, color_hint = password_strength_label(pw)
        colors_map = {
            "red":    SEV_COLORS["Critical"]["fg"],
            "orange": SEV_COLORS["Medium"]["fg"],
            "green":  SEV_COLORS["Low"]["fg"],
        }
        self.strength_lbl.configure(
            text=f"Strength: {label}",
            text_color=colors_map.get(color_hint, TEXT_MUTED)
        )
        self.strength_bar.set(score / 5)

    def _submit(self):
        new_pw  = self.e_new.get().strip()
        confirm = self.e_confirm.get().strip()

        if not self.forced:
            current = self.e_current.get().strip() if self.e_current else ""
            if not verify_password(current, self.user.get("password_hash", "")):
                self.err_lbl.configure(text="Current password is incorrect.")
                return

        ok, err = validate_password(new_pw)
        if not ok:
            self.err_lbl.configure(text=err)
            return

        if new_pw != confirm:
            self.err_lbl.configure(text="Passwords do not match.")
            return

        new_hash = hash_password_for_update(new_pw)
        update_user_password(self.user["id"], new_hash)

        messagebox.showinfo(
            "Password Updated",
            "Your password has been updated successfully!" +
            ("\nYou now have full admin access." if self.forced else ""),
            parent=self
        )
        if self.on_success:
            self.on_success()
        self.destroy()
