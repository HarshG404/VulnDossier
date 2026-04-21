"""
raise_request_window.py — VulnDossier New/Edit Pentest Request (v2.2)
  • User: pentester fields auto-filled from profile (no manual entry)
  • Admin: choose self or "other user" for pentester
  • All requests select an assigned admin by email
  • Admin requests skip approval → Waiting to start
  • Normal user requests → Request Pending
"""
import customtkinter as ctk
from tkinter import messagebox
from ui.theme import *
from database.db_manager import (
    create_project, update_project_status,
    update_project_full, get_admin_emails
)
from auth.auth_manager import is_admin
from utils.security import sanitize_text, sanitize_scope


class RaiseRequestWindow(ctk.CTkToplevel):
    def __init__(self, parent, current_user: dict,
                 on_success=None, existing_project=None):
        super().__init__(parent)
        self.current_user     = current_user
        self.on_success       = on_success
        self.existing_project = existing_project
        self.is_edit          = existing_project is not None
        self._admin_is_self   = True  # Only used when current user is admin

        title = "Edit Request" if self.is_edit else "Raise Pentest Request"
        self.title(title)
        self.geometry("660x820")
        self.resizable(True, True)
        self.configure(fg_color=DARK_BG)
        self.grab_set()
        self._build()

    def _build(self):
        ep = self.existing_project or {}

        hdr = ctk.CTkFrame(self, fg_color=PANEL_BG, corner_radius=0)
        hdr.pack(fill="x")
        icon = "✏️" if self.is_edit else "📋"
        ctk.CTkLabel(hdr,
                     text=f"{icon}  {'Edit' if self.is_edit else 'New'} Pentest Request",
                     font=FONT_HEADING, text_color=TEXT_PRIMARY).pack(
            side="left", padx=20, pady=14)

        # Banner
        if is_admin(self.current_user):
            bg, fg, txt = (SEV_COLORS["Low"]["bg"], SEV_COLORS["Low"]["fg"],
                           "👑  Admin request — goes directly to 'Waiting to start'.")
        else:
            bg, fg, txt = (SEV_COLORS["Informational"]["bg"],
                           SEV_COLORS["Informational"]["fg"],
                           "📨  Request sent to your assigned admin for approval.")
        banner = ctk.CTkFrame(self, fg_color=bg, corner_radius=0)
        banner.pack(fill="x")
        ctk.CTkLabel(banner, text=txt, font=FONT_SMALL,
                     text_color=fg).pack(padx=20, pady=8, anchor="w")

        self._scroll = ctk.CTkScrollableFrame(self, fg_color=DARK_BG)
        self._scroll.pack(fill="both", expand=True)

        self._build_form(ep)

    def _build_form(self, ep):
        scroll = self._scroll
        for w in scroll.winfo_children():
            w.destroy()

        def section(title):
            f = ctk.CTkFrame(scroll, fg_color=PANEL_BG, corner_radius=CARD_RADIUS)
            f.pack(fill="x", padx=20, pady=(12, 0))
            ctk.CTkLabel(f, text=title, font=FONT_SUBHEAD,
                         text_color=ACCENT).pack(anchor="w", padx=16, pady=(12, 4))
            return f

        def field(frame, label, val="", ph="", required=True):
            ctk.CTkLabel(frame,
                         text=f"{label}{' *' if required else ''}",
                         font=FONT_SMALL, text_color=TEXT_MUTED,
                         anchor="w").pack(padx=16, pady=(6, 2), fill="x")
            e = ctk.CTkEntry(frame, height=ENTRY_HEIGHT, placeholder_text=ph,
                             fg_color=CARD_BG, border_color=BORDER,
                             text_color=TEXT_PRIMARY)
            e.pack(padx=16, fill="x")
            if val:
                e.insert(0, str(val))
            return e

        def dropdown(frame, label, values, current=""):
            ctk.CTkLabel(frame, text=f"{label} *", font=FONT_SMALL,
                         text_color=TEXT_MUTED, anchor="w").pack(
                padx=16, pady=(6, 2), fill="x")
            v = ctk.StringVar(value=current if current else values[0])
            ctk.CTkOptionMenu(frame, values=values, variable=v,
                              fg_color=CARD_BG, button_color=ACCENT,
                              button_hover_color=ACCENT_HOVER,
                              text_color=TEXT_PRIMARY,
                              dropdown_fg_color=PANEL_BG).pack(padx=16, fill="x")
            return v

        def textarea(frame, label, height=70, val="", required=True):
            ctk.CTkLabel(frame,
                         text=f"{label}{' *' if required else ''}",
                         font=FONT_SMALL, text_color=TEXT_MUTED,
                         anchor="w").pack(padx=16, pady=(6, 2), fill="x")
            t = ctk.CTkTextbox(frame, height=height, fg_color=CARD_BG,
                               border_color=BORDER, text_color=TEXT_PRIMARY,
                               font=FONT_BODY)
            t.pack(padx=16, fill="x")
            if val:
                t.insert("1.0", val)
            return t

        # ── Section 1: Project Info ──
        s1 = section("Project Information")
        self.e_name   = field(s1, "Project Name",
                              ep.get("project_name", ""),
                              "e.g. AcmeCorp Web App Pentest")
        self.e_ref    = field(s1, "Project ID",
                              ep.get("project_ref_id", ""),
                              "Optional (e.g. PROJ-2026-01)", False)
        self.e_type   = dropdown(s1, "Project Type",
                                 ["Web Application","API","Mobile","Network",
                                  "Cloud","Thick Client","IoT"],
                                 ep.get("project_type", ""))
        self.e_crit   = dropdown(s1, "Criticality",
                                 ["Critical","High","Medium","Low"],
                                 ep.get("criticality", ""))
        self.e_client = field(s1, "Client / Company Name",
                              ep.get("client_name", ""),
                              "e.g. AcmeCorp Pvt. Ltd.")
        self.e_scope  = textarea(s1,
                                 "Scope (URLs / APK / IPA / IP / Swagger)",
                                 height=70, val=ep.get("scope", ""))
        self.e_reason = textarea(s1, "Reason for Pentest",
                                 height=60, val=ep.get("reason", ""))
        self.e_walk   = dropdown(s1, "Walkthrough Done?",
                                 ["Yes","No"],
                                 ep.get("walkthrough_done", ""))
        ctk.CTkLabel(s1, text="", height=6).pack()

        # ── Section 2: Schedule ──
        s2 = section("Schedule")
        row = ctk.CTkFrame(s2, fg_color="transparent")
        row.pack(padx=16, fill="x")
        row.columnconfigure((0, 1), weight=1)
        for col_i, (lbl, attr, val) in enumerate([
            ("Start Date *", "e_start", ep.get("start_date", "")),
            ("End Date *",   "e_end",   ep.get("end_date", "")),
        ]):
            ctk.CTkLabel(row, text=lbl, font=FONT_SMALL,
                         text_color=TEXT_MUTED, anchor="w").grid(
                row=0, column=col_i, sticky="w",
                pady=(6, 2), padx=(0, 8) if col_i == 0 else 0)
            e = ctk.CTkEntry(row, height=ENTRY_HEIGHT,
                             placeholder_text="YYYY-MM-DD",
                             fg_color=CARD_BG, border_color=BORDER,
                             text_color=TEXT_PRIMARY)
            e.grid(row=1, column=col_i, sticky="ew",
                   padx=(0, 8) if col_i == 0 else 0)
            if val:
                e.insert(0, val)
            setattr(self, attr, e)
        ctk.CTkLabel(s2, text="", height=6).pack()

        # ── Section 3: Pentester ──────────────────────────────────────────────
        s3 = section("Pentester Details")

        if is_admin(self.current_user) and not self.is_edit:
            # Admin can choose self or other
            ctk.CTkLabel(s3, text="Pentester for this project *",
                         font=FONT_SMALL, text_color=TEXT_MUTED, anchor="w").pack(
                padx=16, pady=(8, 4), fill="x")
            self._pt_choice = ctk.StringVar(value="self")
            choice_row = ctk.CTkFrame(s3, fg_color=CARD_BG, corner_radius=8)
            choice_row.pack(padx=16, fill="x", pady=(0, 4))
            ctk.CTkRadioButton(choice_row, text="Myself (admin)",
                               variable=self._pt_choice, value="self",
                               text_color=TEXT_PRIMARY, fg_color=ACCENT,
                               command=self._toggle_pentester_fields).pack(
                side="left", padx=14, pady=10)
            ctk.CTkRadioButton(choice_row, text="Another pentester",
                               variable=self._pt_choice, value="other",
                               text_color=TEXT_PRIMARY, fg_color=ACCENT,
                               command=self._toggle_pentester_fields).pack(
                side="left", padx=(0, 14), pady=10)

        # Pentester fields (may be shown/hidden for admin)
        self._pt_frame = ctk.CTkFrame(s3, fg_color="transparent")
        self._pt_frame.pack(fill="x")

        pt_name  = (ep.get("pentester_name", "") or
                    self.current_user.get("username", ""))
        pt_email = (ep.get("pentester_email", "") or
                    self.current_user.get("email", ""))

        ctk.CTkLabel(self._pt_frame, text="Pentester Name *",
                     font=FONT_SMALL, text_color=TEXT_MUTED, anchor="w").pack(
            padx=16, pady=(6, 2), fill="x")
        self.e_ptname = ctk.CTkEntry(self._pt_frame, height=ENTRY_HEIGHT,
                                      placeholder_text="Full name",
                                      fg_color=CARD_BG, border_color=BORDER,
                                      text_color=TEXT_PRIMARY)
        self.e_ptname.pack(padx=16, fill="x")
        self.e_ptname.insert(0, pt_name)

        ctk.CTkLabel(self._pt_frame, text="Pentester Email *",
                     font=FONT_SMALL, text_color=TEXT_MUTED, anchor="w").pack(
            padx=16, pady=(6, 2), fill="x")
        self.e_ptemail = ctk.CTkEntry(self._pt_frame, height=ENTRY_HEIGHT,
                                       placeholder_text="pentester@company.com",
                                       fg_color=CARD_BG, border_color=BORDER,
                                       text_color=TEXT_PRIMARY)
        self.e_ptemail.pack(padx=16, fill="x")
        self.e_ptemail.insert(0, pt_email)

        # Make fields read-only for non-admin (auto-filled)
        if not is_admin(self.current_user) and not self.is_edit:
            self.e_ptname.configure(state="disabled",
                                    text_color=TEXT_MUTED,
                                    fg_color=DARK_BG)
            self.e_ptemail.configure(state="disabled",
                                     text_color=TEXT_MUTED,
                                     fg_color=DARK_BG)
            ctk.CTkLabel(s3,
                         text="ℹ️  Pentester details auto-filled from your profile.",
                         font=FONT_SMALL,
                         text_color=TEXT_MUTED).pack(
                anchor="w", padx=16, pady=(4, 0))

        self.e_classify = dropdown(s3, "Classification",
                                   ["CONFIDENTIAL","RESTRICTED","INTERNAL","PUBLIC"],
                                   ep.get("classification", ""))
        ctk.CTkLabel(s3, text="", height=6).pack()

        # ── Section 4: Assigned Admin ─────────────────────────────────────────
        s4 = section("Assigned Admin")
        ctk.CTkLabel(s4,
                     text="Select the admin who will review and approve this pentest.",
                     font=FONT_SMALL, text_color=TEXT_MUTED).pack(
            anchor="w", padx=16, pady=(0, 8))

        admins = get_admin_emails()
        if admins:
            admin_options = [f"{a['username']} ({a['email']})" for a in admins]
            admin_emails  = [a["email"] for a in admins]
            self._admin_email_map = dict(zip(admin_options, admin_emails))

            current_assigned = ep.get("assigned_admin_email", "")
            default_option   = admin_options[0]
            for opt, em in self._admin_email_map.items():
                if em == current_assigned:
                    default_option = opt

            ctk.CTkLabel(s4, text="Assigned Admin *", font=FONT_SMALL,
                         text_color=TEXT_MUTED, anchor="w").pack(
                padx=16, pady=(0, 2), fill="x")
            self.e_admin_choice = ctk.StringVar(value=default_option)
            ctk.CTkOptionMenu(s4, values=admin_options,
                              variable=self.e_admin_choice,
                              fg_color=CARD_BG, button_color=ACCENT,
                              button_hover_color=ACCENT_HOVER,
                              text_color=TEXT_PRIMARY,
                              dropdown_fg_color=PANEL_BG).pack(
                padx=16, fill="x")
        else:
            ctk.CTkLabel(s4,
                         text="⚠️  No admin accounts found. Please create an admin first.",
                         font=FONT_SMALL,
                         text_color=SEV_COLORS["Critical"]["fg"]).pack(
                padx=16, pady=(0, 8), anchor="w")
            self.e_admin_choice = None
            self._admin_email_map = {}
        ctk.CTkLabel(s4, text="", height=6).pack()

        # ── Submit ──
        self.err_lbl = ctk.CTkLabel(scroll, text="", font=FONT_SMALL,
                                    text_color=SEV_COLORS["Critical"]["fg"],
                                    wraplength=580)
        self.err_lbl.pack(pady=(10, 4))

        btn_text = "Save Changes" if self.is_edit else "Submit Request"
        ctk.CTkButton(scroll, text=btn_text, height=BTN_HEIGHT + 4,
                      corner_radius=BTN_RADIUS, fg_color=ACCENT,
                      hover_color=ACCENT_HOVER, font=FONT_BTN,
                      command=self._submit).pack(padx=20, pady=(0, 8), fill="x")
        ctk.CTkButton(scroll, text="Cancel", height=BTN_HEIGHT,
                      corner_radius=BTN_RADIUS, fg_color="transparent",
                      border_color=BORDER, border_width=1,
                      text_color=TEXT_MUTED, hover_color=CARD_BG,
                      font=FONT_BODY, command=self.destroy).pack(
            padx=20, pady=(0, 20), fill="x")

    def _toggle_pentester_fields(self):
        is_self = getattr(self, "_pt_choice",
                          ctk.StringVar(value="self")).get() == "self"
        if is_self:
            self.e_ptname.configure(state="disabled",
                                    text_color=TEXT_MUTED, fg_color=DARK_BG)
            self.e_ptemail.configure(state="disabled",
                                     text_color=TEXT_MUTED, fg_color=DARK_BG)
            self.e_ptname.delete(0, "end")
            self.e_ptname.insert(0, self.current_user.get("username", ""))
            self.e_ptemail.delete(0, "end")
            self.e_ptemail.insert(0, self.current_user.get("email", ""))
        else:
            self.e_ptname.configure(state="normal",
                                    text_color=TEXT_PRIMARY, fg_color=CARD_BG)
            self.e_ptemail.configure(state="normal",
                                     text_color=TEXT_PRIMARY, fg_color=CARD_BG)
            self.e_ptname.delete(0, "end")
            self.e_ptemail.delete(0, "end")

    def _g(self, w):
        try:
            return w.get("1.0", "end").strip()
        except Exception:
            try:
                return w.get().strip()
            except Exception:
                return ""

    def _submit(self):
        g = self._g
        required = {
            "Project Name":    g(self.e_name),
            "Client Name":     g(self.e_client),
            "Scope":           g(self.e_scope),
            "Reason":          g(self.e_reason),
            "Pentester Name":  g(self.e_ptname),
            "Pentester Email": g(self.e_ptemail),
            "Start Date":      g(self.e_start),
            "End Date":        g(self.e_end),
        }
        for label, val in required.items():
            if not val:
                self.err_lbl.configure(text=f"'{label}' is required.")
                return

        name_val, err = sanitize_text(g(self.e_name), 100, "Project Name")
        if err:
            self.err_lbl.configure(text=err); return
        scope_val, err = sanitize_scope(g(self.e_scope))
        if err:
            self.err_lbl.configure(text=err); return

        # Get assigned admin email
        assigned_admin = ""
        if self.e_admin_choice and self._admin_email_map:
            assigned_admin = self._admin_email_map.get(
                self.e_admin_choice.get(), "")
        if not assigned_admin:
            # Try to get current admin if no selection
            admins = get_admin_emails()
            if admins:
                assigned_admin = admins[0]["email"]

        data = {
            "project_name":    name_val,
            "project_ref_id":  g(self.e_ref),
            "project_type":    self.e_type.get(),
            "start_date":      g(self.e_start),
            "end_date":        g(self.e_end),
            "criticality":     self.e_crit.get(),
            "manager_email":   assigned_admin,
            "client_name":     g(self.e_client),
            "scope":           scope_val,
            "pentester_name":  g(self.e_ptname),
            "pentester_email": g(self.e_ptemail),
            "classification":  self.e_classify.get(),
            "reason":          g(self.e_reason),
            "walkthrough_done": self.e_walk.get(),
            "created_by_email": self.current_user["email"],
        }

        if self.is_edit:
            update_project_full(self.existing_project["id"], data)
            messagebox.showinfo("Saved",
                "✅  Request updated successfully!", parent=self)
        else:
            project_id, _ = create_project(data)
            # Store assigned admin
            from database.db_manager import update_project_field
            update_project_field(project_id, "assigned_admin_email",
                                 assigned_admin)

            if is_admin(self.current_user):
                update_project_status(project_id, "Waiting to start")
                messagebox.showinfo("✅  Project Created",
                    f"'{data['project_name']}' created!\n\n"
                    f"Admin request — status: 'Waiting to start'.\n"
                    f"Open the project and click Start Pentest to begin.",
                    parent=self)
            else:
                # Notify assigned admin
                if assigned_admin:
                    from database.db_manager import create_notification
                    create_notification(
                        assigned_admin,
                        "📨  New Pentest Request",
                        f"{self.current_user['username']} raised a request: "
                        f"'{data['project_name']}' ({data['project_type']}) — "
                        f"{data['criticality']} criticality. Awaiting your approval.",
                        notif_type="request", link_type="project", link_id=project_id
                    )
                messagebox.showinfo("✅  Request Submitted",
                    f"Request for '{data['project_name']}' submitted!\n\n"
                    f"⏳  Assigned admin: {assigned_admin}\n\n"
                    f"The admin will review your request.\n"
                    f"You will see 'Waiting to start' once approved.",
                    parent=self)

        if self.on_success:
            self.on_success()
        self.destroy()
