"""
admin_panel_window.py — VulnDossier Admin Panel v2.4
Tabs:
  📨 Raised Requests | 📝 Admin Review | 🏢 Org Access
  👥 Users | 📋 All Projects | 📧 Email | 📄 Report | 🔍 Audit
"""
import customtkinter as ctk
from tkinter import messagebox
from ui.theme import *
from database.db_manager import (
    get_all_users, update_user_role, set_user_active,
    get_all_projects, get_login_audit, get_pending_requests,
    approve_project_request, reject_project_request,
    set_admin_review_note, add_project_message,
    update_project_status, mark_report_emailed,
    get_org_access_requests_for_admin,
    approve_org_access, reject_org_access,
    create_notification, broadcast_notification_to_admins
)
from utils.helpers import format_dt, format_date, status_icon, truncate
from utils.email_sender import load_email_config, save_email_config, test_smtp_connection


class AdminPanelWindow(ctk.CTkToplevel):
    def __init__(self, parent, current_user: dict, on_open_project=None):
        super().__init__(parent)
        self.current_user    = current_user
        self.on_open_project = on_open_project
        self.title("VulnDossier — Admin Panel")
        self.geometry("1140x760")
        self.resizable(True, True)
        self.configure(fg_color=DARK_BG)
        self.grab_set()
        self._nav_btns = {}
        self._build()

    def _build(self):
        hdr = ctk.CTkFrame(self, fg_color=PANEL_BG, corner_radius=0, height=56)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="🛡️  Admin Panel",
                     font=FONT_HEADING, text_color=ACCENT).pack(side="left", padx=20)
        ctk.CTkLabel(hdr,
                     text=f"Logged in as: {self.current_user['username']}",
                     font=FONT_SMALL, text_color=TEXT_MUTED).pack(side="right", padx=20)

        body = ctk.CTkFrame(self, fg_color=DARK_BG)
        body.pack(fill="both", expand=True)

        self.sidebar = ctk.CTkFrame(body, fg_color=PANEL_BG, width=215, corner_radius=0)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        self.content = ctk.CTkScrollableFrame(body, fg_color=DARK_BG)
        self.content.pack(side="left", fill="both", expand=True)

        self._build_sidebar()
        self._show_raised_requests()

    def _build_sidebar(self):
        self._nav_btns.clear()
        for w in self.sidebar.winfo_children():
            w.destroy()

        ctk.CTkLabel(self.sidebar, text="ADMIN MENU", font=FONT_SMALL,
                     text_color=TEXT_MUTED).pack(anchor="w", padx=16, pady=(20, 8))

        items = [
            ("📨  Raised Requests",  self._show_raised_requests,          "requests"),
            ("📝  Admin Review",     self._show_admin_review_projects,     "review"),
            ("🏢  Org Access",       self._show_org_access_requests,       "orgaccess"),
            ("👥  Users",            self._show_users,                    "users"),
            ("📋  All Projects",     self._show_all_projects,             "projects"),
            ("📧  Email Settings",   self._show_email_settings,           "email"),
            ("📄  Report Settings",  self._show_report_settings,          "rset"),
            ("🔍  Audit Log",        self._show_audit_log,                "audit"),
        ]
        for text, cmd, key in items:
            btn = ctk.CTkButton(
                self.sidebar, text=text, height=38,
                corner_radius=BTN_RADIUS,
                fg_color="transparent",
                hover_color=CARD_BG,
                text_color=TEXT_PRIMARY,
                font=FONT_BODY, anchor="w",
                command=lambda c=cmd, k=key: self._nav(c, k)
            )
            btn.pack(fill="x", padx=10, pady=2)
            self._nav_btns[key] = btn

        ctk.CTkFrame(self.sidebar, fg_color=BORDER, height=1).pack(
            fill="x", padx=10, pady=10)
        ctk.CTkButton(self.sidebar, text="❌  Close", height=38,
                      corner_radius=BTN_RADIUS,
                      fg_color="transparent", hover_color=CARD_BG,
                      text_color=TEXT_MUTED, font=FONT_BODY, anchor="w",
                      command=self.destroy).pack(fill="x", padx=10, pady=2)

        self._set_nav_active("requests")

    def _nav(self, cmd, key):
        self._set_nav_active(key)
        cmd()

    def _set_nav_active(self, key):
        for k, btn in self._nav_btns.items():
            if k == key:
                btn.configure(fg_color=CARD_BG, text_color=ACCENT,
                              border_width=1, border_color=ACCENT)
            else:
                btn.configure(fg_color="transparent", text_color=TEXT_PRIMARY,
                              border_width=0)

    def _clear(self):
        for w in self.content.winfo_children():
            w.destroy()

    def _section(self, title):
        ctk.CTkLabel(self.content, text=title, font=FONT_HEADING,
                     text_color=TEXT_PRIMARY).pack(anchor="w", padx=20, pady=(16, 4))
        ctk.CTkFrame(self.content, fg_color=ACCENT, height=2).pack(
            fill="x", padx=20, pady=(0, 12))

    # ── Raised Requests ───────────────────────────────────────────────────────

    def _show_raised_requests(self):
        self._clear()
        self._section("📨  Raised Requests — Awaiting Approval")
        projects = get_pending_requests()
        if not projects:
            ctk.CTkLabel(self.content, text="No pending requests at this time. ✅",
                         font=FONT_BODY, text_color=TEXT_MUTED).pack(padx=20, pady=24)
            return
        for p in projects:
            card = ctk.CTkFrame(self.content, fg_color=PANEL_BG, corner_radius=CARD_RADIUS)
            card.pack(fill="x", padx=20, pady=6)
            hdr = ctk.CTkFrame(card, fg_color=CARD_BG, corner_radius=CARD_RADIUS)
            hdr.pack(fill="x")
            ctk.CTkLabel(hdr,
                         text=f"📋  {p['project_name']}  —  {p['client_name']}",
                         font=FONT_SUBHEAD, text_color=TEXT_PRIMARY,
                         anchor="w").pack(side="left", padx=14, pady=(10, 4))
            ctk.CTkLabel(hdr, text=f"Criticality: {p.get('criticality','')}",
                         font=FONT_SMALL, text_color=TEXT_MUTED).pack(side="right", padx=14)
            for line in [
                f"Raised by: {p['created_by_email']}  |  Type: {p['project_type']}",
                f"Pentester: {p['pentester_name']} ({p['pentester_email']})",
                f"Period: {format_date(p['start_date'])} → {format_date(p['end_date'])}",
                f"Scope: {truncate(p.get('scope',''), 80)}",
            ]:
                ctk.CTkLabel(card, text=line, font=FONT_SMALL,
                             text_color=TEXT_MUTED, anchor="w").pack(
                    anchor="w", padx=14, pady=1)
            if p.get("reason"):
                ctk.CTkLabel(card, text=f"Reason: {truncate(p['reason'], 80)}",
                             font=FONT_SMALL, text_color=TEXT_MUTED, anchor="w").pack(
                    anchor="w", padx=14, pady=1)
            btn_row = ctk.CTkFrame(card, fg_color="transparent")
            btn_row.pack(fill="x", padx=14, pady=(8, 12))
            ctk.CTkButton(btn_row, text="✅  Approve",
                          height=BTN_HEIGHT - 4, width=100, corner_radius=BTN_RADIUS,
                          fg_color=SEV_COLORS["Low"]["bg"], hover_color=CARD_BG,
                          text_color=SEV_COLORS["Low"]["fg"], font=FONT_BTN,
                          command=lambda pid=p["id"], pn=p["project_name"],
                          pe=p["created_by_email"]: self._approve(pid, pn, pe)
                          ).pack(side="left", padx=(0, 6))
            ctk.CTkButton(btn_row, text="❌  Reject",
                          height=BTN_HEIGHT - 4, width=90, corner_radius=BTN_RADIUS,
                          fg_color=SEV_COLORS["Critical"]["bg"], hover_color=CARD_BG,
                          text_color=SEV_COLORS["Critical"]["fg"], font=FONT_BODY,
                          command=lambda pid=p["id"], pn=p["project_name"],
                          pe=p["created_by_email"]: self._reject(pid, pn, pe)
                          ).pack(side="left", padx=(0, 6))
            if self.on_open_project:
                ctk.CTkButton(btn_row, text="🔍  Review",
                              height=BTN_HEIGHT - 4, width=100, corner_radius=BTN_RADIUS,
                              fg_color=CARD_BG, hover_color=BORDER,
                              text_color=TEXT_PRIMARY, font=FONT_BODY,
                              command=lambda proj=p:
                              self.on_open_project(proj)).pack(side="left")

    def _approve(self, project_id, project_name, requester_email):
        ok = messagebox.askyesno("Approve",
            f"Approve '{project_name}'?\n\nStatus → Waiting to start.", parent=self)
        if ok:
            approve_project_request(project_id)
            create_notification(requester_email,
                "✅  Pentest Request Approved",
                f"Your request for '{project_name}' has been approved! "
                f"You can now start the pentest.",
                notif_type="approval", link_type="project", link_id=project_id)
            messagebox.showinfo("Approved",
                f"'{project_name}' approved!\nUser notified.", parent=self)
            self._show_raised_requests()

    def _reject(self, project_id, project_name, requester_email):
        win = ctk.CTkToplevel(self)
        win.title("Reject Request")
        win.geometry("480x250")
        win.configure(fg_color=DARK_BG)
        win.grab_set()
        ctk.CTkLabel(win, text=f"Reject: {project_name}",
                     font=FONT_HEADING, text_color=TEXT_PRIMARY).pack(padx=20, pady=(18, 8))
        ctk.CTkLabel(win, text="Reason (will be shown to user):",
                     font=FONT_SMALL, text_color=TEXT_MUTED).pack(padx=20, anchor="w")
        txt = ctk.CTkTextbox(win, height=80, fg_color=CARD_BG,
                             border_color=BORDER, text_color=TEXT_PRIMARY, font=FONT_BODY)
        txt.pack(padx=20, fill="x", pady=4)

        def confirm():
            reason = txt.get("1.0", "end").strip()
            reject_project_request(project_id, reason)
            create_notification(requester_email,
                "❌  Pentest Request Rejected",
                f"Your request for '{project_name}' was rejected."
                + (f" Reason: {reason}" if reason else ""),
                notif_type="rejection", link_type="project", link_id=project_id)
            win.destroy()
            messagebox.showinfo("Rejected", f"'{project_name}' rejected.", parent=self)
            self._show_raised_requests()

        ctk.CTkButton(win, text="Confirm Rejection",
                      height=BTN_HEIGHT, corner_radius=BTN_RADIUS,
                      fg_color=SEV_COLORS["Critical"]["bg"], hover_color=CARD_BG,
                      text_color=SEV_COLORS["Critical"]["fg"],
                      font=FONT_BTN, command=confirm).pack(padx=20, pady=10, fill="x")

    # ── Admin Review ──────────────────────────────────────────────────────────

    def _show_admin_review_projects(self):
        self._clear()
        self._section("📝  Admin Review — Approve & Generate Reports")
        projects = [p for p in get_all_projects() if p.get("status") == "Admin Review"]
        if not projects:
            ctk.CTkLabel(self.content, text="No projects in Admin Review. ✅",
                         font=FONT_BODY, text_color=TEXT_MUTED).pack(padx=20, pady=24)
            return
        for p in projects:
            card = ctk.CTkFrame(self.content, fg_color=PANEL_BG, corner_radius=CARD_RADIUS)
            card.pack(fill="x", padx=20, pady=6)
            hdr = ctk.CTkFrame(card, fg_color=CARD_BG, corner_radius=CARD_RADIUS)
            hdr.pack(fill="x")
            ctk.CTkLabel(hdr,
                         text=f"📋  {p['project_name']}  —  {p['client_name']}",
                         font=FONT_SUBHEAD, text_color=TEXT_PRIMARY, anchor="w").pack(
                side="left", padx=14, pady=10)
            ctk.CTkLabel(hdr,
                         text="📧 Report Sent" if p.get("report_emailed") else "⏳ Awaiting",
                         font=FONT_SMALL,
                         text_color=ACCENT if p.get("report_emailed") else TEXT_MUTED).pack(
                side="right", padx=14)
            ctk.CTkLabel(card,
                         text=f"Pentester: {p['pentester_name']} ({p['pentester_email']})",
                         font=FONT_SMALL, text_color=TEXT_MUTED, anchor="w").pack(
                anchor="w", padx=14, pady=(4, 2))
            if p.get("executive_summary"):
                ctk.CTkLabel(card,
                             text=f"Summary: {truncate(p['executive_summary'], 100)}",
                             font=FONT_SMALL, text_color=TEXT_MUTED, anchor="w").pack(
                    anchor="w", padx=14, pady=2)
            btn_row = ctk.CTkFrame(card, fg_color="transparent")
            btn_row.pack(fill="x", padx=14, pady=(8, 12))
            ctk.CTkButton(btn_row, text="✅  Approve & Email Report",
                          height=BTN_HEIGHT, corner_radius=BTN_RADIUS,
                          fg_color=ACCENT, hover_color=ACCENT_HOVER, font=FONT_BTN,
                          command=lambda proj=p: self._approve_and_email(proj)).pack(
                side="left", padx=(0, 8), fill="x", expand=True)
            ctk.CTkButton(btn_row, text="📝  Request Changes",
                          height=BTN_HEIGHT, width=155, corner_radius=BTN_RADIUS,
                          fg_color=SEV_COLORS["Medium"]["bg"], hover_color=CARD_BG,
                          text_color=SEV_COLORS["Medium"]["fg"], font=FONT_BODY,
                          command=lambda proj=p: self._request_changes(proj)).pack(
                side="left", padx=(0, 8))
            if self.on_open_project:
                ctk.CTkButton(btn_row, text="🔍  Open",
                              height=BTN_HEIGHT, width=80, corner_radius=BTN_RADIUS,
                              fg_color=CARD_BG, hover_color=BORDER,
                              text_color=TEXT_PRIMARY, font=FONT_BODY,
                              command=lambda proj=p:
                              self.on_open_project(proj)).pack(side="left")

    def _approve_and_email(self, project):
        ok = messagebox.askyesno("Approve & Email",
            f"Approve '{project['project_name']}'?\n\n"
            f"Reports will be generated and emailed to:\n{project['pentester_email']}",
            parent=self)
        if not ok:
            return
        try:
            from utils.report_builder import generate_reports
            from utils.otp_manager import send_report_email
            result = generate_reports(project["id"],
                                      f"{project['project_name']}_FinalReport")
            update_project_status(project["id"], "Completed")
            ok2, msg = send_report_email(
                to_email       = project["pentester_email"],
                pentester_name = project["pentester_name"],
                project_name   = project["project_name"],
                client_name    = project["client_name"],
                pdf_path       = result["pdf"],
                docx_path      = result["docx"],
            )
            mark_report_emailed(project["id"])
            create_notification(project["pentester_email"],
                "📄  Pentest Report Ready",
                f"Your report for '{project['project_name']}' has been approved and "
                f"{'emailed to you.' if ok2 else 'saved locally (email failed).'}",
                notif_type="report", link_type="project", link_id=project["id"])
            if ok2:
                messagebox.showinfo("✅  Done",
                    f"Reports generated and emailed to {project['pentester_email']}!\n"
                    f"Project marked Completed. Also saved to:\n{result['folder']}",
                    parent=self)
            else:
                messagebox.showwarning("Saved (Email Failed)",
                    f"Reports saved to:\n{result['folder']}\n\nEmail: {msg}",
                    parent=self)
            self._show_admin_review_projects()
        except Exception as e:
            messagebox.showerror("Error", str(e), parent=self)

    def _request_changes(self, project):
        win = ctk.CTkToplevel(self)
        win.title("Request Changes")
        win.geometry("520x300")
        win.configure(fg_color=DARK_BG)
        win.grab_set()
        ctk.CTkLabel(win, text="Request Changes from Pentester",
                     font=FONT_HEADING, text_color=TEXT_PRIMARY).pack(padx=20, pady=(18, 4))
        ctk.CTkLabel(win,
                     text="Your note will appear in the project. Project returns to Running.",
                     font=FONT_SMALL, text_color=TEXT_MUTED).pack(padx=20, pady=(0, 8))
        txt = ctk.CTkTextbox(win, height=100, fg_color=CARD_BG,
                             border_color=BORDER, text_color=TEXT_PRIMARY, font=FONT_BODY)
        txt.pack(padx=20, fill="x")

        def send():
            note = txt.get("1.0", "end").strip()
            if not note:
                return
            set_admin_review_note(project["id"], note)
            add_project_message(project["id"], "admin", "Admin",
                                f"Changes requested: {note}", "admin_note")
            update_project_status(project["id"], "Running")
            create_notification(project["pentester_email"],
                "💬  Changes Requested by Admin",
                f"Admin has requested changes for '{project['project_name']}': {note[:80]}",
                notif_type="admin_note", link_type="project", link_id=project["id"])
            win.destroy()
            messagebox.showinfo("Sent",
                "Note sent. Project returned to Running.", parent=self)
            self._show_admin_review_projects()

        ctk.CTkButton(win, text="Send & Return to Running",
                      height=BTN_HEIGHT, corner_radius=BTN_RADIUS,
                      fg_color=ACCENT, hover_color=ACCENT_HOVER,
                      font=FONT_BTN, command=send).pack(padx=20, pady=12, fill="x")

    # ── Org Access ────────────────────────────────────────────────────────────

    def _show_org_access_requests(self):
        self._clear()
        self._section("🏢  Org Access Requests & Permissions")
        from database.db_manager import (
            get_org_access_requests_for_admin, get_all_org_permissions,
            revoke_org_access, set_org_access_expiry
        )
        from utils.helpers import format_dt, format_date

        # Active permissions section
        all_perms = [p for p in get_all_org_permissions() if p.get("is_active", 1)]
        if all_perms:
            ctk.CTkLabel(self.content, text="Active Permissions",
                         font=FONT_SUBHEAD, text_color=ACCENT).pack(
                anchor="w", padx=20, pady=(0, 4))
            for p in all_perms:
                exp     = p.get("expires_at", "")
                exp_txt = f"  |  Expires: {format_date(exp)}" if exp else "  |  No expiry"
                card = ctk.CTkFrame(self.content,
                                    fg_color=SEV_COLORS["Low"]["bg"], corner_radius=8)
                card.pack(fill="x", padx=20, pady=3)
                row = ctk.CTkFrame(card, fg_color="transparent")
                row.pack(fill="x", padx=12, pady=8)
                ctk.CTkLabel(row,
                             text=f"✅  {p.get('username','?')} ({p['user_email']})  "
                                  f"—  {p['permission'].upper()}{exp_txt}",
                             font=FONT_SMALL,
                             text_color=SEV_COLORS["Low"]["fg"],
                             anchor="w").pack(side="left", fill="x", expand=True)
                ctk.CTkButton(row, text="🚫 Revoke", height=26, width=80,
                              corner_radius=BTN_RADIUS,
                              fg_color=SEV_COLORS["Critical"]["bg"],
                              hover_color=CARD_BG,
                              text_color=SEV_COLORS["Critical"]["fg"],
                              font=FONT_SMALL,
                              command=lambda uid=p["user_id"],
                              un=p.get("username","?"):
                              self._revoke_org(uid, un)).pack(side="right")
            ctk.CTkFrame(self.content, fg_color=BORDER, height=1).pack(
                fill="x", padx=20, pady=10)

        # Pending requests
        requests = get_org_access_requests_for_admin(self.current_user["email"])
        pending  = [r for r in requests if r["status"] == "Pending"]
        past     = [r for r in requests if r["status"] != "Pending"]

        if not pending and not all_perms and not past:
            ctk.CTkLabel(self.content, text="No org access requests yet.",
                         font=FONT_BODY, text_color=TEXT_MUTED).pack(padx=20, pady=20)
            return

        if pending:
            ctk.CTkLabel(self.content, text="Pending Requests",
                         font=FONT_SUBHEAD, text_color=ACCENT).pack(
                anchor="w", padx=20, pady=(0, 4))

        for req in pending:
            card = ctk.CTkFrame(self.content, fg_color=PANEL_BG,
                                corner_radius=CARD_RADIUS)
            card.pack(fill="x", padx=20, pady=5)
            hdr2 = ctk.CTkFrame(card, fg_color=CARD_BG, corner_radius=CARD_RADIUS)
            hdr2.pack(fill="x")
            ctk.CTkLabel(hdr2,
                         text=f"📨  {req['user_name']} ({req['user_email']})",
                         font=FONT_SUBHEAD, text_color=TEXT_PRIMARY,
                         anchor="w").pack(side="left", padx=14, pady=10)
            ctk.CTkLabel(hdr2, text="Pending", font=FONT_SMALL,
                         text_color=TEXT_MUTED).pack(side="right", padx=14)

            if req.get("note"):
                ctk.CTkLabel(card,
                             text=f"Reason: {req['note'][:140]}",
                             font=FONT_SMALL, text_color=TEXT_MUTED,
                             anchor="w", wraplength=700).pack(
                    anchor="w", padx=14, pady=(6, 2))

            # Permission radio buttons
            ctrl = ctk.CTkFrame(card, fg_color="transparent")
            ctrl.pack(fill="x", padx=14, pady=(8, 2))
            perm_var = ctk.StringVar(value=req.get("permission", "read"))
            ctk.CTkLabel(ctrl, text="Permission:",
                         font=FONT_SMALL, text_color=TEXT_MUTED).pack(side="left")
            ctk.CTkRadioButton(ctrl, text="Read Only",
                               variable=perm_var, value="read",
                               text_color=TEXT_PRIMARY, fg_color=ACCENT).pack(
                side="left", padx=(8, 0))
            ctk.CTkRadioButton(ctrl, text="Read + Write",
                               variable=perm_var, value="write",
                               text_color=TEXT_PRIMARY, fg_color=ACCENT).pack(
                side="left", padx=(12, 0))

            # Expiry date
            exp_row = ctk.CTkFrame(card, fg_color="transparent")
            exp_row.pack(fill="x", padx=14, pady=(4, 2))
            ctk.CTkLabel(exp_row, text="Expiry date (optional):",
                         font=FONT_SMALL, text_color=TEXT_MUTED).pack(side="left")
            exp_entry = ctk.CTkEntry(exp_row, height=28, width=130,
                                     placeholder_text="YYYY-MM-DD",
                                     fg_color=CARD_BG, border_color=BORDER,
                                     text_color=TEXT_PRIMARY, font=FONT_SMALL)
            exp_entry.pack(side="left", padx=8)
            ctk.CTkLabel(exp_row, text="(blank = no expiry)",
                         font=("Segoe UI", 9), text_color=TEXT_MUTED).pack(side="left")

            # Admin note
            note_row = ctk.CTkFrame(card, fg_color="transparent")
            note_row.pack(fill="x", padx=14, pady=(4, 2))
            ctk.CTkLabel(note_row, text="Note to user (optional):",
                         font=FONT_SMALL, text_color=TEXT_MUTED).pack(side="left")
            note_entry = ctk.CTkEntry(note_row, height=28,
                                       placeholder_text="e.g. Granted for Q2 audit",
                                       fg_color=CARD_BG, border_color=BORDER,
                                       text_color=TEXT_PRIMARY, font=FONT_SMALL)
            note_entry.pack(side="left", padx=8, fill="x", expand=True)

            # Approve / Reject
            btn_row = ctk.CTkFrame(card, fg_color="transparent")
            btn_row.pack(fill="x", padx=14, pady=(6, 10))
            ctk.CTkButton(btn_row, text="✅  Approve",
                          height=BTN_HEIGHT - 4, width=110,
                          corner_radius=BTN_RADIUS,
                          fg_color=SEV_COLORS["Low"]["bg"], hover_color=CARD_BG,
                          text_color=SEV_COLORS["Low"]["fg"], font=FONT_BTN,
                          command=lambda rid=req["id"], pv=perm_var,
                          ev=exp_entry, nv=note_entry:
                          self._approve_org(rid, pv.get(),
                                            ev.get().strip(),
                                            nv.get().strip())).pack(
                side="left", padx=(0, 8))
            ctk.CTkButton(btn_row, text="❌  Reject",
                          height=BTN_HEIGHT - 4, width=90,
                          corner_radius=BTN_RADIUS,
                          fg_color=SEV_COLORS["Critical"]["bg"], hover_color=CARD_BG,
                          text_color=SEV_COLORS["Critical"]["fg"], font=FONT_BODY,
                          command=lambda rid=req["id"]:
                          self._reject_org(rid)).pack(side="left")

        # Past requests
        if past:
            ctk.CTkFrame(self.content, fg_color=BORDER, height=1).pack(
                fill="x", padx=20, pady=8)
            ctk.CTkLabel(self.content, text="Previous Requests",
                         font=FONT_SUBHEAD, text_color=TEXT_MUTED).pack(
                anchor="w", padx=20, pady=(0, 4))
            for req in past[:8]:
                sc = {"Approved": SEV_COLORS["Low"]["fg"],
                      "Rejected": SEV_COLORS["Critical"]["fg"],
                      "Revoked":  TEXT_MUTED}.get(req["status"], TEXT_MUTED)
                r2 = ctk.CTkFrame(self.content, fg_color=CARD_BG, corner_radius=8)
                r2.pack(fill="x", padx=20, pady=2)
                ctk.CTkLabel(r2,
                             text=f"{req['user_name']} ({req['user_email']})  "
                                  f"—  {req['permission'].upper()}  "
                                  f"—  {req['status']}",
                             font=FONT_SMALL, text_color=sc, anchor="w").pack(
                    padx=12, pady=6, anchor="w")

    def _approve_org(self, request_id, permission, expires_at="", admin_note=""):
        from database.db_manager import approve_org_access, set_org_access_expiry
        import sqlite3, os as _os
        approve_org_access(request_id, self.current_user["email"],
                           permission, admin_note)
        if expires_at:
            DB = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)),
                               "data", "vulndossier.db")
            conn = sqlite3.connect(DB)
            conn.row_factory = sqlite3.Row
            req = conn.execute(
                "SELECT user_id FROM org_access_requests WHERE id=?",
                (request_id,)).fetchone()
            conn.close()
            if req:
                set_org_access_expiry(req["user_id"], expires_at)
        exp_txt = f" (expires {expires_at})" if expires_at else ""
        # Notify user
        import sqlite3 as _sq3, os as _os2
        _DB = _os2.path.join(_os2.path.dirname(_os2.path.dirname(__file__)),
                              "data", "vulndossier.db")
        _conn = _sq3.connect(_DB); _conn.row_factory = _sq3.Row
        _req2 = _conn.execute("SELECT user_email, user_name FROM org_access_requests WHERE id=?",
                              (request_id,)).fetchone()
        _conn.close()
        if _req2:
            create_notification(
                _req2["user_email"],
                "🏢  Org Access Approved",
                f"Your request for org-wide project access has been approved: "
                f"{permission.upper()}{exp_txt}."
                + (f" Note: {admin_note}" if admin_note else ""),
                notif_type="access"
            )
        messagebox.showinfo("✅ Access Granted",
            f"Org access granted: {permission.upper()}{exp_txt}. User notified.", parent=self)
        self._show_org_access_requests()

    def _reject_org(self, request_id):
        from database.db_manager import reject_org_access
        import sqlite3 as _sq3, os as _os3
        _DB3 = _os3.path.join(_os3.path.dirname(_os3.path.dirname(__file__)),
                               "data", "vulndossier.db")
        _conn3 = _sq3.connect(_DB3); _conn3.row_factory = _sq3.Row
        _req3 = _conn3.execute(
            "SELECT user_email FROM org_access_requests WHERE id=?",
            (request_id,)).fetchone()
        _conn3.close()
        reject_org_access(request_id)
        if _req3:
            create_notification(
                _req3["user_email"],
                "🏢  Org Access Request Rejected",
                "Your request for org-wide project access was not approved at this time.",
                notif_type="rejection"
            )
        messagebox.showinfo("Rejected", "Request rejected. User notified.", parent=self)
        self._show_org_access_requests()

    def _revoke_org(self, user_id, username):
        ok = messagebox.askyesno("Revoke Access",
            f"Revoke org access for {username}?\n\n"
            f"They will immediately lose access to All Org Projects.",
            parent=self)
        if ok:
            from database.db_manager import revoke_org_access
            revoke_org_access(user_id)
            # Notify user
            import sqlite3 as _sq4, os as _os4
            _DB4 = _os4.path.join(_os4.path.dirname(_os4.path.dirname(__file__)),
                                   "data", "vulndossier.db")
            _conn4 = _sq4.connect(_DB4); _conn4.row_factory = _sq4.Row
            _urow = _conn4.execute("SELECT email FROM users WHERE id=?",
                                   (user_id,)).fetchone()
            _conn4.close()
            if _urow:
                create_notification(
                    _urow["email"],
                    "🚫  Org Access Revoked",
                    "Your org-wide project access has been revoked by the admin.",
                    notif_type="rejection"
                )
            messagebox.showinfo("Revoked", f"Access revoked for {username}. User notified.",
                                parent=self)
            self._show_org_access_requests()



        # ── Users ─────────────────────────────────────────────────────────────────

    def _show_users(self):
        self._clear()
        self._section("👥  User Management")
        for u in get_all_users():
            is_self  = u["email"] == self.current_user["email"]
            role_icon = "👑" if u.get("role") == "admin" else "👤"
            card = ctk.CTkFrame(self.content, fg_color=PANEL_BG, corner_radius=CARD_RADIUS)
            card.pack(fill="x", padx=20, pady=5)
            left = ctk.CTkFrame(card, fg_color="transparent")
            left.pack(side="left", fill="x", expand=True, padx=14, pady=10)
            ctk.CTkLabel(left,
                         text=f"{role_icon}  {u['username']}  —  {u['email']}",
                         font=FONT_SUBHEAD, text_color=TEXT_PRIMARY, anchor="w").pack(anchor="w")
            status_txt = "Active" if u.get("is_active", 1) else "Suspended"
            ctk.CTkLabel(left,
                         text=f"Role: {u.get('role','user').title()}  |  "
                              f"{status_txt}  |  "
                              f"Joined: {format_date(u.get('created_at',''))}",
                         font=FONT_SMALL, text_color=TEXT_MUTED, anchor="w").pack(anchor="w")
            if not is_self:
                right = ctk.CTkFrame(card, fg_color="transparent")
                right.pack(side="right", padx=14, pady=10)
                if u.get("role") == "admin":
                    ctk.CTkButton(right, text="Remove Admin", height=30, width=110,
                                  corner_radius=BTN_RADIUS,
                                  fg_color=SEV_COLORS["Medium"]["bg"], hover_color=CARD_BG,
                                  text_color=SEV_COLORS["Medium"]["fg"], font=FONT_SMALL,
                                  command=lambda uid=u["id"]:
                                  self._set_user_role(uid, "user")).pack(pady=2)
                else:
                    ctk.CTkButton(right, text="Make Admin", height=30, width=110,
                                  corner_radius=BTN_RADIUS,
                                  fg_color=SEV_COLORS["Informational"]["bg"], hover_color=CARD_BG,
                                  text_color=SEV_COLORS["Informational"]["fg"], font=FONT_SMALL,
                                  command=lambda uid=u["id"]:
                                  self._set_user_role(uid, "admin")).pack(pady=2)
                if u.get("is_active", 1):
                    ctk.CTkButton(right, text="Suspend", height=30, width=110,
                                  corner_radius=BTN_RADIUS,
                                  fg_color=SEV_COLORS["Critical"]["bg"], hover_color=CARD_BG,
                                  text_color=SEV_COLORS["Critical"]["fg"], font=FONT_SMALL,
                                  command=lambda uid=u["id"]:
                                  self._set_active(uid, False)).pack(pady=2)
                else:
                    ctk.CTkButton(right, text="Reactivate", height=30, width=110,
                                  corner_radius=BTN_RADIUS,
                                  fg_color=SEV_COLORS["Low"]["bg"], hover_color=CARD_BG,
                                  text_color=SEV_COLORS["Low"]["fg"], font=FONT_SMALL,
                                  command=lambda uid=u["id"]:
                                  self._set_active(uid, True)).pack(pady=2)
            else:
                ctk.CTkLabel(card, text="(you)", font=FONT_SMALL,
                             text_color=TEXT_MUTED).pack(side="right", padx=14)

    def _set_user_role(self, uid, role):
        update_user_role(uid, role)
        messagebox.showinfo("Updated", f"Role → {role}.", parent=self)
        self._show_users()

    def _set_active(self, uid, active):
        ok = messagebox.askyesno("Confirm",
            f"{'Reactivate' if active else 'Suspend'} this user?", parent=self)
        if ok:
            set_user_active(uid, active)
            self._show_users()

    # ── All Projects ──────────────────────────────────────────────────────────

    def _show_all_projects(self):
        self._clear()
        self._section("📋  All Projects")
        projects = get_all_projects()
        if not projects:
            ctk.CTkLabel(self.content, text="No projects yet.",
                         font=FONT_BODY, text_color=TEXT_MUTED).pack(padx=20, pady=20)
            return
        statuses = ["Request Pending","Waiting to start","Running",
                    "Admin Review","Completed","Hold"]
        summary = ctk.CTkFrame(self.content, fg_color=PANEL_BG, corner_radius=CARD_RADIUS)
        summary.pack(fill="x", padx=20, pady=(0, 12))
        for st in statuses:
            count = sum(1 for p in projects if p.get("status") == st)
            col = ctk.CTkFrame(summary, fg_color=CARD_BG, corner_radius=8)
            col.pack(side="left", padx=5, pady=8, expand=True, fill="x")
            ctk.CTkLabel(col, text=str(count), font=("Segoe UI", 18, "bold"),
                         text_color=STATUS_COLORS.get(st, TEXT_PRIMARY)).pack(pady=(8, 0))
            ctk.CTkLabel(col, text=st, font=FONT_SMALL,
                         text_color=TEXT_MUTED, wraplength=90).pack(pady=(0, 8))
        for p in projects:
            status   = p.get("status", "")
            status_c = STATUS_COLORS.get(status, TEXT_MUTED)
            card = ctk.CTkFrame(self.content, fg_color=PANEL_BG, corner_radius=CARD_RADIUS)
            card.pack(fill="x", padx=20, pady=5)
            hdr = ctk.CTkFrame(card, fg_color=CARD_BG, corner_radius=CARD_RADIUS)
            hdr.pack(fill="x")
            ctk.CTkLabel(hdr,
                         text=f"{status_icon(status)}  {p['project_name']}  —  {p['client_name']}",
                         font=FONT_SUBHEAD, text_color=TEXT_PRIMARY, anchor="w").pack(
                side="left", padx=14, pady=(10, 4))
            ctk.CTkLabel(hdr, text=status, font=FONT_SMALL,
                         text_color=status_c).pack(side="right", padx=14)
            ctk.CTkLabel(card,
                         text=f"Pentester: {p['pentester_name']} ({p['pentester_email']})  |  "
                              f"{format_date(p['start_date'])} → {format_date(p['end_date'])}",
                         font=FONT_SMALL, text_color=TEXT_MUTED, anchor="w").pack(
                anchor="w", padx=14, pady=(2, 8))
            if self.on_open_project:
                ctk.CTkButton(card, text="Open →", height=28,
                              corner_radius=BTN_RADIUS,
                              fg_color="transparent", hover_color=CARD_BG,
                              text_color=ACCENT, font=FONT_SMALL,
                              command=lambda proj=p:
                              self.on_open_project(proj)).pack(anchor="e", padx=14, pady=(0, 8))

    # ── Email Settings ────────────────────────────────────────────────────────

    def _show_email_settings(self):
        self._clear()
        self._section("📧  Email / SMTP Settings")
        cfg = load_email_config()
        info = ctk.CTkFrame(self.content,
                            fg_color=SEV_COLORS["Informational"]["bg"],
                            corner_radius=CARD_RADIUS)
        info.pack(fill="x", padx=20, pady=(0, 12))
        ctk.CTkLabel(info,
                     text="Gmail: smtp.gmail.com port 587.\n"
                          "Use App Password (NOT your Gmail login password).\n"
                          "Generate at: myaccount.google.com/apppasswords\n"
                          "(Enable 2-Step Verification on your Google account first)",
                     font=FONT_SMALL,
                     text_color=SEV_COLORS["Informational"]["fg"],
                     justify="left").pack(padx=14, pady=12, anchor="w")

        card = ctk.CTkFrame(self.content, fg_color=PANEL_BG, corner_radius=CARD_RADIUS)
        card.pack(fill="x", padx=20, pady=(0, 12))

        self.email_enabled = ctk.BooleanVar(value=cfg.get("enabled", False))
        ctk.CTkSwitch(card, text="Enable Email Sending",
                      variable=self.email_enabled, font=FONT_BODY,
                      text_color=TEXT_PRIMARY,
                      button_color=ACCENT, progress_color=ACCENT).pack(
            anchor="w", padx=16, pady=(14, 8))

        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=(0, 6))
        row.columnconfigure((0, 1), weight=1)
        ctk.CTkLabel(row, text="SMTP Host *", font=FONT_SMALL,
                     text_color=TEXT_MUTED, anchor="w").grid(row=0, column=0, sticky="w", pady=(0,2))
        self.e_host = ctk.CTkEntry(row, height=ENTRY_HEIGHT,
                                   placeholder_text="smtp.gmail.com",
                                   fg_color=CARD_BG, border_color=BORDER, text_color=TEXT_PRIMARY)
        self.e_host.grid(row=1, column=0, sticky="ew", padx=(0, 8))
        if cfg.get("smtp_host"):
            self.e_host.insert(0, cfg["smtp_host"])
        ctk.CTkLabel(row, text="SMTP Port *", font=FONT_SMALL,
                     text_color=TEXT_MUTED, anchor="w").grid(row=0, column=1, sticky="w", pady=(0,2))
        self.e_port = ctk.CTkEntry(row, height=ENTRY_HEIGHT,
                                   placeholder_text="587",
                                   fg_color=CARD_BG, border_color=BORDER, text_color=TEXT_PRIMARY)
        self.e_port.grid(row=1, column=1, sticky="ew")
        if cfg.get("smtp_port"):
            self.e_port.insert(0, str(cfg["smtp_port"]))

        def field(label, key, ph="", is_pw=False):
            ctk.CTkLabel(card, text=label, font=FONT_SMALL,
                         text_color=TEXT_MUTED, anchor="w").pack(padx=16, pady=(10, 2), fill="x")
            e = ctk.CTkEntry(card, height=ENTRY_HEIGHT, placeholder_text=ph,
                             show="•" if is_pw else "",
                             fg_color=CARD_BG, border_color=BORDER, text_color=TEXT_PRIMARY)
            e.pack(padx=16, fill="x")
            val = cfg.get(key, "")
            if val:
                e.insert(0, str(val))
            return e

        self.e_sender_email = field("Sender Email *",   "sender_email",   "your@gmail.com")
        self.e_sender_pw    = field("App Password *",    "sender_password","xxxx xxxx xxxx xxxx", True)
        self.e_sender_name  = field("Sender Display Name", "sender_name", "VulnDossier")

        self.use_tls = ctk.BooleanVar(value=cfg.get("use_tls", True))
        ctk.CTkSwitch(card, text="Use TLS (keep ON)",
                      variable=self.use_tls, font=FONT_BODY, text_color=TEXT_PRIMARY,
                      button_color=ACCENT, progress_color=ACCENT).pack(
            anchor="w", padx=16, pady=(12, 16))

        self.email_status = ctk.CTkLabel(self.content, text="", font=FONT_SMALL,
                                          text_color=ACCENT, wraplength=800)
        self.email_status.pack(padx=20, pady=(0, 6))
        btns = ctk.CTkFrame(self.content, fg_color="transparent")
        btns.pack(fill="x", padx=20, pady=(0, 16))
        ctk.CTkButton(btns, text="💾  Save Settings", height=BTN_HEIGHT,
                      corner_radius=BTN_RADIUS, fg_color=ACCENT, hover_color=ACCENT_HOVER,
                      font=FONT_BTN, command=self._save_email).pack(side="left", padx=(0, 8))
        ctk.CTkButton(btns, text="🔌  Test Connection", height=BTN_HEIGHT,
                      corner_radius=BTN_RADIUS, fg_color=CARD_BG, hover_color=BORDER,
                      text_color=TEXT_PRIMARY, font=FONT_BODY,
                      command=self._test_email).pack(side="left")

    def _save_email(self):
        cfg = {
            "enabled":         self.email_enabled.get(),
            "smtp_host":       self.e_host.get().strip(),
            "smtp_port":       int(self.e_port.get().strip() or 587),
            "use_tls":         self.use_tls.get(),
            "sender_email":    self.e_sender_email.get().strip(),
            "sender_password": self.e_sender_pw.get().strip(),
            "sender_name":     self.e_sender_name.get().strip() or "VulnDossier",
        }
        if save_email_config(cfg):
            self.email_status.configure(text="✅  Settings saved!", text_color=ACCENT)
        else:
            self.email_status.configure(text="❌  Failed to save.",
                                         text_color=SEV_COLORS["Critical"]["fg"])

    def _test_email(self):
        cfg = {
            "smtp_host":       self.e_host.get().strip(),
            "smtp_port":       int(self.e_port.get().strip() or 587),
            "use_tls":         self.use_tls.get(),
            "sender_email":    self.e_sender_email.get().strip(),
            "sender_password": self.e_sender_pw.get().strip(),
        }
        self.email_status.configure(text="Testing...", text_color=TEXT_MUTED)
        self.update()
        ok, msg = test_smtp_connection(cfg)
        color = ACCENT if ok else SEV_COLORS["Critical"]["fg"]
        self.email_status.configure(text=f"{'✅' if ok else '❌'}  {msg}", text_color=color)

    # ── Report Settings ───────────────────────────────────────────────────────

    def _show_report_settings(self):
        self._clear()
        self._section("📄  Report Branding Settings")
        ctk.CTkLabel(self.content,
                     text="Configure company logo, colors, and report layout.",
                     font=FONT_BODY, text_color=TEXT_MUTED).pack(padx=20, pady=(0, 12), anchor="w")
        ctk.CTkButton(self.content, text="⚙️  Open Report Settings",
                      height=BTN_HEIGHT + 4, corner_radius=BTN_RADIUS,
                      fg_color=ACCENT, hover_color=ACCENT_HOVER, font=FONT_BTN,
                      command=lambda: __import__("ui.report_settings_window",
                                                  fromlist=["ReportSettingsWindow"]
                                                  ).ReportSettingsWindow(self)).pack(
            padx=20, anchor="w")

    # ── Audit Log ─────────────────────────────────────────────────────────────

    def _show_audit_log(self):
        self._clear()
        self._section("🔍  Login Audit Log (Last 50)")
        entries = get_login_audit(50)
        if not entries:
            ctk.CTkLabel(self.content, text="No login attempts recorded.",
                         font=FONT_BODY, text_color=TEXT_MUTED).pack(padx=20, pady=20)
            return
        card = ctk.CTkFrame(self.content, fg_color=PANEL_BG, corner_radius=CARD_RADIUS)
        card.pack(fill="x", padx=20)
        for e in entries:
            ok     = bool(e.get("success", 0))
            color  = SEV_COLORS["Low"]["fg"] if ok else SEV_COLORS["Critical"]["fg"]
            icon   = "✓" if ok else "✗"
            row = ctk.CTkFrame(card, fg_color="transparent")
            row.pack(fill="x", padx=14, pady=4)
            ctk.CTkLabel(row, text=f"{icon}  {e.get('identifier','')[:40]}",
                         font=FONT_SMALL, text_color=color,
                         width=280, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=format_dt(e.get("attempted_at", "")),
                         font=FONT_SMALL, text_color=TEXT_MUTED).pack(side="right")
