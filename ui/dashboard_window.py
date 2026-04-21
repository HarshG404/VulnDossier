"""
dashboard_window.py — Main dashboard.
  • Admin users: see Admin Panel button, all projects
  • Normal users: see only their own projects
  • Report Settings removed from normal user sidebar
  • Auth code flow respects account type (company vs personal)
"""
import customtkinter as ctk
from tkinter import messagebox, simpledialog
from ui.theme import *
from ui.raise_request_window import RaiseRequestWindow
from ui.project_work_window import ProjectWorkWindow
from auth.auth_manager import is_admin
from database.db_manager import (
    get_projects_by_user, get_all_projects,
    verify_admin_code, count_user_completed
)
from utils.helpers import format_date, format_dt, status_icon, truncate


class DashboardWindow(ctk.CTk):
    def __init__(self, current_user: dict, login_win):
        super().__init__()
        self.current_user = current_user
        self.login_win    = login_win
        self.title(f"VulnDossier v2.0  —  {current_user['username']}")
        self.geometry("1200x760")
        self.minsize(900, 600)
        self.configure(fg_color=DARK_BG)
        ctk.set_appearance_mode(CTK_THEME)
        self.protocol("WM_DELETE_WINDOW", self._quit)
        self._build()

    def _quit(self):
        self.login_win.destroy()
        self.destroy()

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build(self):
        # Top nav
        nav = ctk.CTkFrame(self, fg_color=PANEL_BG, corner_radius=0, height=56)
        nav.pack(fill="x")
        nav.pack_propagate(False)

        ctk.CTkLabel(nav, text="🔐  VulnDossier v2.0",
                     font=FONT_HEADING, text_color=ACCENT).pack(side="left", padx=20)

        user = self.current_user
        role_badge = "  👑 Admin" if is_admin(user) else ""
        ctk.CTkLabel(nav,
                     text=f"{user['username']}{role_badge}",
                     font=FONT_SMALL, text_color=TEXT_MUTED).pack(side="right", padx=20)
        ctk.CTkButton(nav, text="Logout", height=30, width=80,
                      corner_radius=BTN_RADIUS, fg_color="transparent",
                      border_color=BORDER, border_width=1,
                      text_color=TEXT_MUTED, hover_color=CARD_BG,
                      font=FONT_SMALL, command=self._logout).pack(side="right", padx=(0, 8))

        # Notification bell
        from ui.notification_panel import NotificationBell
        self._notif_bell = NotificationBell(nav, self.current_user["email"])
        self._notif_bell.pack(side="right", padx=(0, 4))

        # Body
        body = ctk.CTkFrame(self, fg_color=DARK_BG)
        body.pack(fill="both", expand=True)

        self.sidebar = ctk.CTkFrame(body, fg_color=PANEL_BG, width=230, corner_radius=0)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        self.content_frame = ctk.CTkFrame(body, fg_color=DARK_BG)
        self.content_frame.pack(side="left", fill="both", expand=True)

        self._build_sidebar()
        self._show_my_projects()

    def _build_sidebar(self):
        for w in self.sidebar.winfo_children():
            w.destroy()

        ctk.CTkLabel(self.sidebar, text="MAIN MENU", font=FONT_SMALL,
                     text_color=TEXT_MUTED).pack(anchor="w", padx=16, pady=(24, 8))

        # Stats
        completed   = count_user_completed(self.current_user["email"])
        my_projects = get_projects_by_user(self.current_user["email"])
        running     = sum(1 for p in my_projects if p["status"] == "Running")

        for label, val, color in [
            ("My Projects", len(my_projects), ACCENT),
            ("Running",     running,          SEV_COLORS["Low"]["fg"]),
            ("Completed",   completed,        SEV_COLORS["Informational"]["fg"]),
        ]:
            c = ctk.CTkFrame(self.sidebar, fg_color=CARD_BG, corner_radius=8)
            c.pack(fill="x", padx=10, pady=3)
            ctk.CTkLabel(c, text=str(val),
                         font=("Segoe UI", 20, "bold"), text_color=color).pack(
                anchor="w", padx=12, pady=(8, 0))
            ctk.CTkLabel(c, text=label, font=FONT_SMALL,
                         text_color=TEXT_MUTED).pack(anchor="w", padx=12, pady=(0, 8))

        ctk.CTkFrame(self.sidebar, fg_color=BORDER, height=1).pack(fill="x", padx=10, pady=12)

        def nav(text, cmd, accent=False):
            ctk.CTkButton(self.sidebar, text=text, height=40,
                          corner_radius=BTN_RADIUS,
                          fg_color=ACCENT if accent else "transparent",
                          hover_color=ACCENT_HOVER if accent else CARD_BG,
                          text_color=WHITE if accent else TEXT_PRIMARY,
                          font=FONT_BODY, anchor="w",
                          command=cmd).pack(fill="x", padx=10, pady=2)

        nav("📋  My Projects",        self._show_my_projects)
        nav("➕  Raise New Request",  self._raise_request, accent=True)
        nav("📊  Total Completed",    self._show_completed_count)

        # Org access — only for non-admin users
        from auth.auth_manager import is_admin as _is_admin
        from database.db_manager import get_user_org_permission
        if not _is_admin(self.current_user):
            org_perm = get_user_org_permission(self.current_user["id"])
            if org_perm:
                nav("🏢  All Org Projects",   self._show_org_projects)
            else:
                nav("🏢  Request Org Access", self._request_org_access)

        # Admin-only items
        if is_admin(self.current_user):
            ctk.CTkFrame(self.sidebar, fg_color=BORDER, height=1).pack(
                fill="x", padx=10, pady=8)
            ctk.CTkLabel(self.sidebar, text="ADMIN", font=FONT_SMALL,
                         text_color=ACCENT).pack(anchor="w", padx=16, pady=(0, 6))
            nav("🛡️  Admin Panel",    self._open_admin_panel, accent=False)
            nav("🏢  All Org Projects", self._show_all_projects)

        ctk.CTkFrame(self.sidebar, fg_color=BORDER, height=1).pack(fill="x", padx=10, pady=10)
        nav("👤  My Profile",          self._open_profile)
        nav("🚪  Logout",             self._logout)

    def _clear_content(self):
        for w in self.content_frame.winfo_children():
            w.destroy()

    def _section_label(self, frame, text):
        ctk.CTkLabel(frame, text=text, font=FONT_HEADING,
                     text_color=TEXT_PRIMARY).pack(anchor="w", padx=24, pady=(20, 4))
        ctk.CTkFrame(frame, fg_color=ACCENT, height=2).pack(
            fill="x", padx=24, pady=(0, 14))

    # ── Views ─────────────────────────────────────────────────────────────────

    def _show_my_projects(self):
        self._clear_content()
        scroll = ctk.CTkScrollableFrame(self.content_frame, fg_color=DARK_BG)
        scroll.pack(fill="both", expand=True)
        self._section_label(scroll, "📋  My Projects")

        projects = get_projects_by_user(self.current_user["email"])
        if not projects:
            ctk.CTkLabel(scroll,
                         text="No projects yet. Use 'Raise New Request' to create your first pentest.",
                         font=FONT_BODY, text_color=TEXT_MUTED).pack(padx=24, pady=20)
            return
        for p in projects:
            self._project_card(scroll, p)

    def _show_all_projects(self):
        """Admin-only — no extra auth code needed since already admin."""
        if not is_admin(self.current_user):
            messagebox.showerror("Access Denied",
                "This section is restricted to administrators.", parent=self)
            return

        self._clear_content()
        scroll = ctk.CTkScrollableFrame(self.content_frame, fg_color=DARK_BG)
        scroll.pack(fill="both", expand=True)
        self._section_label(scroll, "🏢  All Organisation Projects")

        projects = get_all_projects()
        if not projects:
            ctk.CTkLabel(scroll, text="No projects in the system.",
                         font=FONT_BODY, text_color=TEXT_MUTED).pack(padx=24, pady=20)
            return

        # Status summary
        statuses = ["Request Pending", "Waiting to start", "Running",
                    "Admin Review", "Completed", "Hold"]
        summary = ctk.CTkFrame(scroll, fg_color=PANEL_BG, corner_radius=CARD_RADIUS)
        summary.pack(fill="x", padx=24, pady=(0, 12))
        for st in statuses:
            count = sum(1 for p in projects if p["status"] == st)
            col = ctk.CTkFrame(summary, fg_color=CARD_BG, corner_radius=8)
            col.pack(side="left", padx=5, pady=8, expand=True, fill="x")
            ctk.CTkLabel(col, text=str(count),
                         font=("Segoe UI", 18, "bold"),
                         text_color=STATUS_COLORS.get(st, TEXT_PRIMARY)).pack(pady=(8, 0))
            ctk.CTkLabel(col, text=st, font=FONT_SMALL,
                         text_color=TEXT_MUTED, wraplength=90).pack(pady=(0, 8))

        for p in projects:
            self._project_card(scroll, p, show_owner=True)

    def _show_completed_count(self):
        self._clear_content()
        scroll = ctk.CTkScrollableFrame(self.content_frame, fg_color=DARK_BG)
        scroll.pack(fill="both", expand=True)
        self._section_label(scroll, "📊  Completed Pentests")

        completed      = count_user_completed(self.current_user["email"])
        all_projects   = get_projects_by_user(self.current_user["email"])
        completed_list = [p for p in all_projects if p["status"] == "Completed"]

        big = ctk.CTkFrame(scroll, fg_color=PANEL_BG, corner_radius=CARD_RADIUS)
        big.pack(fill="x", padx=24, pady=(0, 12))
        ctk.CTkLabel(big, text=str(completed),
                     font=("Segoe UI", 56, "bold"), text_color=ACCENT).pack(pady=(20, 0))
        ctk.CTkLabel(big, text="Total Pentests Completed",
                     font=FONT_HEADING, text_color=TEXT_MUTED).pack(pady=(0, 20))

        if completed_list:
            self._section_label(scroll, "Completed Projects")
            for p in completed_list:
                self._project_card(scroll, p)

    # ── Project Card ──────────────────────────────────────────────────────────

    def _project_card(self, parent, p, show_owner=False):
        from datetime import date as ddate
        status    = p.get("status", "")
        status_c  = STATUS_COLORS.get(status, TEXT_MUTED)

        # Deadline check
        deadline_passed = False
        pre_start       = False
        try:
            end_d   = ddate.fromisoformat(p.get("end_date",""))
            start_d = ddate.fromisoformat(p.get("start_date",""))
            today   = ddate.today()
            if status in ("Running","Waiting to start") and today > end_d:
                deadline_passed = True
            if status == "Waiting to start" and today < start_d:
                pre_start = True
        except Exception:
            pass

        card = ctk.CTkFrame(parent, fg_color=PANEL_BG, corner_radius=CARD_RADIUS)
        card.pack(fill="x", padx=24, pady=6)

        # Deadline warning banner
        if deadline_passed:
            db_warn = ctk.CTkFrame(card, fg_color=SEV_COLORS["Critical"]["bg"],
                                   corner_radius=0)
            db_warn.pack(fill="x")
            ctk.CTkLabel(db_warn,
                         text=f"⏰  Engagement Overdue — end date {p.get('end_date','')} has passed.",
                         font=FONT_SMALL,
                         text_color=SEV_COLORS["Critical"]["fg"]).pack(
                padx=14, pady=6, anchor="w")

        if pre_start:
            ps_warn = ctk.CTkFrame(card, fg_color=SEV_COLORS["Medium"]["bg"],
                                   corner_radius=0)
            ps_warn.pack(fill="x")
            ctk.CTkLabel(ps_warn,
                         text=f"⏳  Waiting for start date ({p.get('start_date','')}) — "
                              f"raise a pre-start request if you need to start earlier.",
                         font=FONT_SMALL,
                         text_color=SEV_COLORS["Medium"]["fg"]).pack(
                padx=14, pady=6, anchor="w")

        # Admin review note banner
        if p.get("admin_review_note"):
            note_frame = ctk.CTkFrame(card,
                                      fg_color=SEV_COLORS["Informational"]["bg"],
                                      corner_radius=0)
            note_frame.pack(fill="x")
            ctk.CTkLabel(note_frame,
                         text=f"💬  Admin note: {p['admin_review_note'][:120]}",
                         font=FONT_SMALL,
                         text_color=SEV_COLORS["Informational"]["fg"],
                         wraplength=700, anchor="w").pack(
                padx=14, pady=6, anchor="w")

        hdr = ctk.CTkFrame(card, fg_color=CARD_BG, corner_radius=CARD_RADIUS)
        hdr.pack(fill="x")

        left = ctk.CTkFrame(hdr, fg_color="transparent")
        left.pack(side="left", fill="x", expand=True, padx=14, pady=10)
        ctk.CTkLabel(left,
                     text=f"{status_icon(status)}  {p['project_name']}",
                     font=FONT_SUBHEAD, text_color=TEXT_PRIMARY,
                     anchor="w").pack(anchor="w")
        ctk.CTkLabel(left,
                     text=f"Client: {p['client_name']}  |  {p['project_type']}  |  "
                          f"{format_date(p['start_date'])} → {format_date(p['end_date'])}",
                     font=FONT_SMALL, text_color=TEXT_MUTED,
                     anchor="w").pack(anchor="w", pady=(2, 0))
        if show_owner:
            ctk.CTkLabel(left,
                         text=f"Pentester: {p.get('pentester_name','')} ({p.get('pentester_email','')})",
                         font=FONT_SMALL, text_color=TEXT_MUTED,
                         anchor="w").pack(anchor="w")

        right = ctk.CTkFrame(hdr, fg_color="transparent")
        right.pack(side="right", padx=14, pady=10)
        ctk.CTkLabel(right, text=status, font=FONT_SMALL,
                     text_color=status_c).pack(anchor="e")
        ctk.CTkLabel(right, text=f"Criticality: {p.get('criticality','')}",
                     font=FONT_SMALL, text_color=TEXT_MUTED).pack(anchor="e", pady=(2,0))

        # Button row
        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.pack(fill="x", padx=14, pady=(4, 10))

        ctk.CTkButton(btn_row, text="Open →",
                      height=30, width=90, corner_radius=BTN_RADIUS,
                      fg_color="transparent", hover_color=CARD_BG,
                      text_color=ACCENT, font=FONT_BODY,
                      command=lambda proj=p: self._open_project(proj)).pack(
            side="left", padx=(0, 6))

        # Edit/Delete only for own pending requests
        is_own = p.get("created_by_email") == self.current_user.get("email")
        if status == "Request Pending" and is_own:
            ctk.CTkButton(btn_row, text="✏️ Edit",
                          height=30, width=70, corner_radius=BTN_RADIUS,
                          fg_color="transparent", hover_color=CARD_BG,
                          text_color=TEXT_MUTED, font=FONT_SMALL,
                          command=lambda proj=p: self._edit_request(proj)).pack(
                side="left", padx=(0, 6))
            ctk.CTkButton(btn_row, text="🗑️ Delete",
                          height=30, width=80, corner_radius=BTN_RADIUS,
                          fg_color="transparent", hover_color=SEV_COLORS["Critical"]["bg"],
                          text_color=SEV_COLORS["Critical"]["fg"], font=FONT_SMALL,
                          command=lambda proj=p: self._delete_request(proj)).pack(
                side="left")

    def _edit_request(self, project):
        RaiseRequestWindow(self, self.current_user,
                           on_success=self._show_my_projects,
                           existing_project=project)

    def _delete_request(self, project):
        from tkinter import messagebox as mb2
        ok = mb2.askyesno("Delete Request",
            f"Delete request for '{project['project_name']}'?\n\n"
            f"This cannot be undone.",
            parent=self)
        if ok:
            from database.db_manager import delete_project
            delete_project(project["id"])
            self._show_my_projects()

    def _show_org_projects(self):
        from database.db_manager import get_all_projects, get_user_org_permission
        from ui.project_work_window import ProjectWorkWindow
        perm = get_user_org_permission(self.current_user["id"])
        # Org access users view other people's projects — always read_only
        # (write permission only affects their own projects, not org-wide ones)
        read_only = True

        self._clear_content()
        scroll = ctk.CTkScrollableFrame(self.content_frame, fg_color=DARK_BG)
        scroll.pack(fill="both", expand=True)
        perm_badge = f"👁️ {perm.upper()} access"
        self._section_label(scroll, f"🏢  All Org Projects  — {perm_badge}")
        projects = get_all_projects()
        if not projects:
            ctk.CTkLabel(scroll, text="No projects in the system.",
                         font=FONT_BODY, text_color=TEXT_MUTED).pack(padx=24, pady=20)
            return
        for p in projects:
            card = ctk.CTkFrame(scroll, fg_color=PANEL_BG, corner_radius=CARD_RADIUS)
            card.pack(fill="x", padx=24, pady=5)
            hdr = ctk.CTkFrame(card, fg_color=CARD_BG, corner_radius=CARD_RADIUS)
            hdr.pack(fill="x")
            status   = p.get("status","")
            status_c = STATUS_COLORS.get(status, TEXT_MUTED)
            ctk.CTkLabel(hdr,
                         text=f"{status_icon(status)}  {p['project_name']}  —  {p['client_name']}",
                         font=FONT_SUBHEAD, text_color=TEXT_PRIMARY, anchor="w").pack(
                side="left", padx=14, pady=(10,4))
            ctk.CTkLabel(hdr, text=status, font=FONT_SMALL,
                         text_color=status_c).pack(side="right", padx=14)
            ctk.CTkLabel(card,
                         text=f"Pentester: {p['pentester_name']}  |  "
                              f"{format_date(p['start_date'])} → {format_date(p['end_date'])}  |  {p['project_type']}",
                         font=FONT_SMALL, text_color=TEXT_MUTED, anchor="w").pack(
                anchor="w", padx=14, pady=(2,8))
            ctk.CTkButton(card, text="Open →",
                          height=30, corner_radius=BTN_RADIUS,
                          fg_color="transparent", hover_color=CARD_BG,
                          text_color=ACCENT, font=FONT_SMALL,
                          command=lambda proj=p, ro=read_only:
                          self._open_project(proj, read_only=ro)).pack(
                anchor="e", padx=14, pady=(0,8))

    def _request_org_access(self):
        from ui.org_access_window import OrgAccessRequestWindow
        OrgAccessRequestWindow(self, self.current_user,
                                on_success=self._build_sidebar)

    def _open_project(self, project, read_only: bool = False):
        from database.db_manager import get_project_by_id
        fresh = get_project_by_id(project["id"])
        ProjectWorkWindow(self, fresh, self.current_user,
                          on_close=self._build_sidebar,
                          read_only=read_only)

    # ── Actions ───────────────────────────────────────────────────────────────

    def _raise_request(self):
        RaiseRequestWindow(self, self.current_user,
                           on_success=self._build_sidebar)

    def _open_admin_panel(self):
        if not is_admin(self.current_user):
            messagebox.showerror("Access Denied",
                "Admin panel requires administrator privileges.", parent=self)
            return
        from ui.admin_panel_window import AdminPanelWindow
        AdminPanelWindow(self, self.current_user,
                         on_open_project=self._open_project)

    def _open_profile(self):
        from ui.profile_window import ProfileWindow
        def on_updated(updated_user):
            self.current_user = updated_user
            self._build_sidebar()
        ProfileWindow(self, self.current_user, on_profile_updated=on_updated)

    def _logout(self):
        ok = messagebox.askyesno("Logout", "Are you sure you want to logout?", parent=self)
        if ok:
            self.destroy()
            self.login_win.deiconify()
