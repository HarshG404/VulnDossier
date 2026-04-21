"""
org_access_window.py — Request org-wide project access from an admin.
Users select an admin, choose read/write, add a note explaining their need.
"""
import customtkinter as ctk
from tkinter import messagebox
from ui.theme import *
from database.db_manager import (
    get_admin_emails, request_org_access, get_my_org_access_requests,
    get_user_org_permission
)


class OrgAccessRequestWindow(ctk.CTkToplevel):
    def __init__(self, parent, current_user: dict, on_success=None):
        super().__init__(parent)
        self.current_user = current_user
        self.on_success   = on_success
        self.title("Request Org-Wide Project Access")
        self.geometry("560x620")
        self.resizable(False, True)
        self.configure(fg_color=DARK_BG)
        self.grab_set()
        self._build()

    def _build(self):
        hdr = ctk.CTkFrame(self, fg_color=PANEL_BG, corner_radius=0)
        hdr.pack(fill="x")
        ctk.CTkLabel(hdr, text="🏢  Org-Wide Access Request",
                     font=FONT_HEADING, text_color=TEXT_PRIMARY).pack(
            side="left", padx=20, pady=14)

        scroll = ctk.CTkScrollableFrame(self, fg_color=DARK_BG)
        scroll.pack(fill="both", expand=True)

        # Current permission
        perm = get_user_org_permission(self.current_user["id"])
        if perm:
            status_card = ctk.CTkFrame(scroll,
                                       fg_color=SEV_COLORS["Low"]["bg"],
                                       corner_radius=CARD_RADIUS)
            status_card.pack(fill="x", padx=20, pady=(12, 0))
            ctk.CTkLabel(status_card,
                         text=f"✅  You already have  '{perm.upper()}'  access to all org projects.",
                         font=FONT_BODY,
                         text_color=SEV_COLORS["Low"]["fg"]).pack(
                padx=14, pady=12, anchor="w")

        # Existing requests
        requests = get_my_org_access_requests(self.current_user["id"])
        if requests:
            ctk.CTkLabel(scroll, text="Your Previous Requests",
                         font=FONT_SUBHEAD, text_color=TEXT_MUTED).pack(
                anchor="w", padx=20, pady=(12, 4))
            for req in requests[:3]:
                rc = ctk.CTkFrame(scroll, fg_color=PANEL_BG, corner_radius=8)
                rc.pack(fill="x", padx=20, pady=3)
                status_color = {
                    "Pending":  TEXT_MUTED,
                    "Approved": SEV_COLORS["Low"]["fg"],
                    "Rejected": SEV_COLORS["Critical"]["fg"],
                }.get(req["status"], TEXT_MUTED)
                ctk.CTkLabel(rc,
                             text=f"{req['permission'].upper()} access → {req['admin_email']}  |  {req['status']}",
                             font=FONT_SMALL, text_color=status_color).pack(
                    anchor="w", padx=12, pady=6)
                if req.get("admin_note"):
                    ctk.CTkLabel(rc,
                                 text=f"Admin note: {req['admin_note']}",
                                 font=FONT_SMALL,
                                 text_color=TEXT_MUTED).pack(
                        anchor="w", padx=12, pady=(0, 6))

        # New request form
        form = ctk.CTkFrame(scroll, fg_color=PANEL_BG, corner_radius=CARD_RADIUS)
        form.pack(fill="x", padx=20, pady=(14, 0))
        ctk.CTkLabel(form, text="Raise New Access Request",
                     font=FONT_SUBHEAD, text_color=ACCENT).pack(
            anchor="w", padx=16, pady=(12, 4))

        # Admin selector
        admins = get_admin_emails()
        if not admins:
            ctk.CTkLabel(form,
                         text="⚠️  No admins found. Ask your admin to set up an account.",
                         font=FONT_SMALL,
                         text_color=SEV_COLORS["Critical"]["fg"]).pack(
                padx=16, pady=10)
            ctk.CTkButton(scroll, text="Close", height=BTN_HEIGHT,
                          corner_radius=BTN_RADIUS, fg_color=CARD_BG,
                          hover_color=BORDER, text_color=TEXT_PRIMARY,
                          font=FONT_BODY, command=self.destroy).pack(
                padx=20, pady=12, fill="x")
            return

        ctk.CTkLabel(form, text="Select Admin to Request From *",
                     font=FONT_SMALL, text_color=TEXT_MUTED, anchor="w").pack(
            padx=16, pady=(8, 2), fill="x")
        admin_options = [f"{a['username']} ({a['email']})" for a in admins]
        self._admin_map = {opt: a["email"] for opt, a in zip(admin_options, admins)}
        self.e_admin = ctk.StringVar(value=admin_options[0])
        ctk.CTkOptionMenu(form, values=admin_options,
                          variable=self.e_admin,
                          fg_color=CARD_BG, button_color=ACCENT,
                          button_hover_color=ACCENT_HOVER,
                          text_color=TEXT_PRIMARY,
                          dropdown_fg_color=PANEL_BG).pack(padx=16, fill="x")

        # Permission type
        ctk.CTkLabel(form, text="Permission Needed *",
                     font=FONT_SMALL, text_color=TEXT_MUTED, anchor="w").pack(
            padx=16, pady=(12, 4), fill="x")
        self.e_perm = ctk.StringVar(value="read")
        perm_row = ctk.CTkFrame(form, fg_color=CARD_BG, corner_radius=8)
        perm_row.pack(padx=16, fill="x", pady=(0, 4))

        ctk.CTkRadioButton(perm_row, text="Read Only (view projects, no changes)",
                           variable=self.e_perm, value="read",
                           text_color=TEXT_PRIMARY, fg_color=ACCENT).pack(
            anchor="w", padx=14, pady=8)
        ctk.CTkRadioButton(perm_row, text="Read + Write (can modify projects)",
                           variable=self.e_perm, value="write",
                           text_color=TEXT_PRIMARY, fg_color=ACCENT).pack(
            anchor="w", padx=14, pady=(0, 8))

        # Note
        ctk.CTkLabel(form, text="Why do you need this access? *",
                     font=FONT_SMALL, text_color=TEXT_MUTED, anchor="w").pack(
            padx=16, pady=(10, 2), fill="x")
        self.e_note = ctk.CTkTextbox(form, height=80, fg_color=CARD_BG,
                                     border_color=BORDER, text_color=TEXT_PRIMARY,
                                     font=FONT_BODY)
        self.e_note.pack(padx=16, fill="x")

        self.err_lbl = ctk.CTkLabel(form, text="", font=FONT_SMALL,
                                    text_color=SEV_COLORS["Critical"]["fg"],
                                    wraplength=480)
        self.err_lbl.pack(padx=16, pady=(8, 4))

        ctk.CTkButton(form, text="Submit Access Request",
                      height=BTN_HEIGHT + 2, corner_radius=BTN_RADIUS,
                      fg_color=ACCENT, hover_color=ACCENT_HOVER,
                      font=FONT_BTN, command=self._submit).pack(
            padx=16, fill="x", pady=(0, 16))

        ctk.CTkButton(scroll, text="Cancel", height=BTN_HEIGHT,
                      corner_radius=BTN_RADIUS, fg_color="transparent",
                      border_color=BORDER, border_width=1,
                      text_color=TEXT_MUTED, hover_color=CARD_BG,
                      font=FONT_BODY, command=self.destroy).pack(
            padx=20, pady=(8, 20), fill="x")

    def _submit(self):
        note = self.e_note.get("1.0", "end").strip()
        if not note:
            self.err_lbl.configure(text="Please explain why you need this access.")
            return

        admin_email = self._admin_map.get(self.e_admin.get(), "")
        if not admin_email:
            self.err_lbl.configure(text="Please select an admin.")
            return

        request_org_access(
            user_id    = self.current_user["id"],
            user_email = self.current_user["email"],
            user_name  = self.current_user["username"],
            admin_email= admin_email,
            permission = self.e_perm.get(),
            note       = note,
        )
        messagebox.showinfo("✅  Request Submitted",
            f"Access request sent to {admin_email}.\n\n"
            f"You will see 'All Org Projects' in your dashboard once approved.",
            parent=self)
        if self.on_success:
            self.on_success()
        self.destroy()
