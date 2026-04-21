"""
project_work_window.py — VulnDossier v2.3
Fixes:
  • Images display in vulnerability list AND detail view
  • Sidebar hides Add/Edit/Remove/Finish/Generate/Removed until Start Pentest clicked
  • Vulnerabilities renumbered by severity after any add/remove
  • Admin review note visible to user
  • POC images embedded in reports under steps to reproduce
"""
import os
import json
import customtkinter as ctk
from tkinter import messagebox
from ui.theme import *
from ui.vuln_form_window import VulnFormWindow
from database.db_manager import (
    get_vulnerabilities, remove_vulnerability,
    update_project_status, update_project_field,
    save_removed_to_txt, get_removed_vulnerabilities,
    update_vulnerability_status, renumber_vulnerabilities,
    set_project_testing_started
)
from utils.helpers import format_dt, format_date, severity_icon, status_icon, truncate
from utils.report_builder import generate_reports, get_output_folder
from utils.helpers import open_folder


class ProjectWorkWindow(ctk.CTkToplevel):
    def __init__(self, parent, project: dict, current_user: dict,
                 on_close=None, read_only: bool = False):
        super().__init__(parent)
        self.project      = project
        self.current_user = current_user
        self.on_close     = on_close
        self.read_only    = read_only   # org-access read-only mode
        self._nav_buttons = {}
        self._img_refs    = []          # prevent GC of CTkImage objects
        self.title(f"VulnDossier — {project['project_name']}")
        self.geometry("1020x760")
        self.resizable(True, True)
        self.configure(fg_color=DARK_BG)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._on_destroy)
        self._build()

    def _on_destroy(self):
        if self.on_close:
            self.on_close()
        self.destroy()

    def _refresh(self):
        from database.db_manager import get_project_by_id
        self.project = get_project_by_id(self.project["id"])
        self._img_refs = []   # Safe to clear only on full rebuild
        for w in self.winfo_children():
            w.destroy()
        self._build()

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build(self):
        p      = self.project
        status = p.get("status", "")
        started = bool(p.get("testing_started", 0))

        # Top bar
        hdr = ctk.CTkFrame(self, fg_color=PANEL_BG, corner_radius=0, height=58)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text=f"{status_icon(status)}  {p['project_name']}",
                     font=FONT_HEADING, text_color=TEXT_PRIMARY).pack(
            side="left", padx=20)
        ctk.CTkLabel(hdr, text=status, font=FONT_SMALL,
                     text_color=STATUS_COLORS.get(status, TEXT_MUTED)).pack(
            side="left", padx=6)
        if self.read_only:
            ctk.CTkLabel(hdr, text="👁️ Read-Only",
                         font=FONT_SMALL, text_color=SEV_COLORS["Medium"]["fg"]).pack(
                side="left", padx=10)
        ctk.CTkLabel(hdr,
                     text=f"Client: {p['client_name']}  |  {p['project_type']}",
                     font=FONT_SMALL, text_color=TEXT_MUTED).pack(side="right", padx=20)

        body = ctk.CTkFrame(self, fg_color=DARK_BG)
        body.pack(fill="both", expand=True)

        self.sidebar = ctk.CTkFrame(body, fg_color=PANEL_BG, width=220, corner_radius=0)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        self.content = ctk.CTkScrollableFrame(body, fg_color=DARK_BG)
        self.content.pack(side="left", fill="both", expand=True)

        self._build_sidebar(status, started)
        self._show_project_description()

    def _build_sidebar(self, status, started):
        for w in self.sidebar.winfo_children():
            w.destroy()
        self._nav_buttons = {}

        ctk.CTkLabel(self.sidebar, text="MENU", font=FONT_SMALL,
                     text_color=TEXT_MUTED).pack(anchor="w", padx=16, pady=(18, 6))

        def nav(text, cmd, key="", accent=False):
            btn = ctk.CTkButton(
                self.sidebar, text=text, height=38,
                corner_radius=BTN_RADIUS,
                fg_color=ACCENT if accent else "transparent",
                hover_color=ACCENT_HOVER if accent else CARD_BG,
                text_color=WHITE if accent else TEXT_PRIMARY,
                font=FONT_BODY, anchor="w",
                command=lambda c=cmd, k=key: self._nav_click(c, k)
            )
            btn.pack(fill="x", padx=10, pady=2)
            if key:
                self._nav_buttons[key] = btn
            return btn

        # Always visible — for everyone including read-only org access
        nav("📋  Project Info",      self._show_project_description, "info")
        nav("🔍  Vulnerabilities",   self._show_vulnerabilities,     "vulns")

        # Read-only mode: only Project Info, Vulnerabilities, Removed Vulns, Close
        if self.read_only:
            nav("🗂️  Removed Vulns", self._show_removed, "removed")
            ctk.CTkFrame(self.sidebar, fg_color=BORDER, height=1).pack(
                fill="x", padx=10, pady=10)
            ctk.CTkLabel(self.sidebar,
                         text="👁️ Read-Only Access",
                         font=FONT_SMALL, text_color=TEXT_MUTED).pack(
                anchor="w", padx=16, pady=(0, 6))
            nav("❌  Close", self._on_destroy)
            self._set_active_nav("info")
            return

        # Full controls for project owner / admin
        if status == "Waiting to start":
            nav("▶️  Start Pentest",  self._start_pentest, "start", accent=True)

        elif status == "Running":
            if started:
                nav("➕  Add Vulnerability",    self._add_vulnerability,    "add",    accent=True)
                nav("✏️  Edit Vulnerability",   self._edit_vulnerability,   "edit")
                nav("🗑️  Remove Vulnerability", self._remove_vulnerability, "remove")
                nav("🏁  Finish Project",       self._finish_project,       "finish")
                nav("⏸️  Put on Hold",           self._put_on_hold,          "hold")
                nav("📄  Generate Reports",     self._generate_reports,     "report")
                nav("🗂️  Removed Vulns",         self._show_removed,         "removed")
            else:
                nav("▶️  Start Pentest",  self._start_pentest, "start", accent=True)

        elif status in ("Admin Review", "Completed"):
            nav("📄  Generate Reports",   self._generate_reports, "report")

        elif status == "Hold":
            nav("▶️  Restart Project",    self._restart_project, "restart", accent=True)
            nav("📌  Hold Reason",         self._show_hold_reason, "holdr")

        ctk.CTkFrame(self.sidebar, fg_color=BORDER, height=1).pack(
            fill="x", padx=10, pady=10)
        nav("❌  Close", self._on_destroy)
        self._set_active_nav("info")

    def _nav_click(self, cmd, key):
        self._set_active_nav(key)
        cmd()

    def _set_active_nav(self, key):
        for k, btn in self._nav_buttons.items():
            if k == key:
                btn.configure(fg_color=CARD_BG, text_color=ACCENT,
                              border_width=1, border_color=ACCENT)
            else:
                btn.configure(fg_color="transparent", text_color=TEXT_PRIMARY,
                              border_width=0)

    # ── Content helpers ────────────────────────────────────────────────────────

    def _clear_content(self):
        # Do NOT reset _img_refs here — images would lose their reference and crash
        # _img_refs is only reset on full window rebuild (_refresh)
        for w in self.content.winfo_children():
            w.destroy()

    def _section_label(self, text):
        ctk.CTkLabel(self.content, text=text, font=FONT_HEADING,
                     text_color=TEXT_PRIMARY).pack(anchor="w", padx=20, pady=(18, 4))
        ctk.CTkFrame(self.content, fg_color=ACCENT, height=2).pack(
            fill="x", padx=20, pady=(0, 12))

    # ── Project Info ──────────────────────────────────────────────────────────

    def _show_project_description(self):
        self._clear_content()
        p = self.project
        self._section_label("📋  Project Description")

        # Admin review note — shown prominently if present
        if p.get("admin_review_note"):
            note_card = ctk.CTkFrame(self.content,
                                     fg_color=SEV_COLORS["Medium"]["bg"],
                                     corner_radius=CARD_RADIUS)
            note_card.pack(fill="x", padx=20, pady=(0, 10))
            ctk.CTkLabel(note_card,
                         text="💬  Admin Review Note — Action Required:",
                         font=FONT_SUBHEAD,
                         text_color=SEV_COLORS["Medium"]["fg"]).pack(
                anchor="w", padx=14, pady=(12, 4))
            ctk.CTkLabel(note_card,
                         text=p["admin_review_note"],
                         font=FONT_BODY,
                         text_color=TEXT_PRIMARY,
                         wraplength=800, justify="left").pack(
                anchor="w", padx=14, pady=(0, 12))

        fields = [
            ("Project Name",       p.get("project_name", "")),
            ("Project ID",         p.get("project_ref_id", "") or "N/A"),
            ("Project Type",       p.get("project_type", "")),
            ("Client / Company",   p.get("client_name", "")),
            ("Criticality",        p.get("criticality", "")),
            ("Status",             p.get("status", "")),
            ("Start Date",         format_date(p.get("start_date", ""))),
            ("End Date",           format_date(p.get("end_date", ""))),
            ("Pentester",          p.get("pentester_name", "")),
            ("Pentester Email",    p.get("pentester_email", "")),
            ("Classification",     p.get("classification", "")),
            ("Scope",              p.get("scope", "")),
            ("Reason for Pentest", p.get("reason", "")),
            ("Walkthrough Done",   p.get("walkthrough_done", "")),
            ("Created At",         format_dt(p.get("created_at", ""))),
        ]

        card = ctk.CTkFrame(self.content, fg_color=PANEL_BG, corner_radius=CARD_RADIUS)
        card.pack(fill="x", padx=20, pady=(0, 12))
        for label, val in fields:
            row = ctk.CTkFrame(card, fg_color="transparent")
            row.pack(fill="x", padx=16, pady=3)
            ctk.CTkLabel(row, text=f"{label}:", font=FONT_SMALL,
                         text_color=TEXT_MUTED, width=165, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=str(val), font=FONT_BODY,
                         text_color=TEXT_PRIMARY, anchor="w",
                         wraplength=640).pack(side="left")

        # Vulnerability summary
        vulns = get_vulnerabilities(p["id"])
        self._section_label(f"🔍  Vulnerabilities ({len(vulns)})")
        if not vulns:
            ctk.CTkLabel(self.content,
                         text="No vulnerabilities added yet.",
                         font=FONT_BODY, text_color=TEXT_MUTED).pack(
                padx=20, pady=8, anchor="w")
        else:
            for v in vulns:
                sev      = v.get("severity", "Low")
                sev_col  = SEV_COLORS.get(sev, {})
                vstatus  = v.get("vuln_status", "Open")
                vs_color = SEV_COLORS["Low"]["fg"] if vstatus == "Closed" \
                    else SEV_COLORS["Critical"]["fg"]
                row = ctk.CTkFrame(self.content, fg_color=PANEL_BG, corner_radius=8)
                row.pack(fill="x", padx=20, pady=3)
                ctk.CTkLabel(row, text=f"{severity_icon(sev)} {v['vuln_id']}",
                             font=FONT_SMALL,
                             text_color=sev_col.get("fg", TEXT_MUTED),
                             width=80).pack(side="left", padx=(12, 4), pady=8)
                ctk.CTkLabel(row, text=v["title"], font=FONT_BODY,
                             text_color=TEXT_PRIMARY, anchor="w").pack(
                    side="left", padx=4)
                ctk.CTkLabel(row, text=f"● {vstatus}", font=FONT_SMALL,
                             text_color=vs_color).pack(side="right", padx=(4, 8))
                ctk.CTkLabel(row,
                             text=f"CVSS {v['cvss_score']} | {sev}",
                             font=FONT_SMALL,
                             text_color=sev_col.get("fg", TEXT_MUTED)).pack(
                    side="right", padx=4)

        if p.get("executive_summary"):
            self._section_label("📝  Executive Summary")
            c2 = ctk.CTkFrame(self.content, fg_color=PANEL_BG,
                               corner_radius=CARD_RADIUS)
            c2.pack(fill="x", padx=20, pady=(0, 12))
            ctk.CTkLabel(c2, text=p["executive_summary"],
                         font=FONT_BODY, text_color=TEXT_PRIMARY,
                         wraplength=800, justify="left").pack(
                padx=16, pady=12, anchor="w")

    # ── Vulnerabilities list ──────────────────────────────────────────────────

    def _show_vulnerabilities(self):
        self._clear_content()
        self._section_label("🔍  All Vulnerabilities")
        vulns = get_vulnerabilities(self.project["id"])
        if not vulns:
            ctk.CTkLabel(self.content,
                         text="No vulnerabilities found.",
                         font=FONT_BODY, text_color=TEXT_MUTED).pack(
                padx=20, pady=20, anchor="w")
            return

        for v in vulns:
            sev      = v.get("severity", "Low")
            sev_col  = SEV_COLORS.get(sev, {})
            vstatus  = v.get("vuln_status", "Open")
            vs_color = SEV_COLORS["Low"]["fg"] if vstatus == "Closed" \
                else SEV_COLORS["Critical"]["fg"]
            poc_paths = self._load_poc(v)  # used only for count display

            card = ctk.CTkFrame(self.content, fg_color=PANEL_BG,
                                corner_radius=CARD_RADIUS)
            card.pack(fill="x", padx=20, pady=6)

            # Header
            hdr = ctk.CTkFrame(card, fg_color=sev_col.get("bg", CARD_BG),
                               corner_radius=CARD_RADIUS)
            hdr.pack(fill="x")
            ctk.CTkLabel(hdr,
                         text=f"{severity_icon(sev)}  {v['vuln_id']}  —  {v['title']}",
                         font=FONT_SUBHEAD,
                         text_color=sev_col.get("fg", TEXT_PRIMARY)).pack(
                side="left", padx=14, pady=10)
            ctk.CTkLabel(hdr,
                         text=f"CVSS {v['cvss_score']}  |  {sev}",
                         font=FONT_SMALL,
                         text_color=sev_col.get("fg", TEXT_MUTED)).pack(
                side="right", padx=14)

            # Open/Close status toggle
            if not self.read_only:
                status_row = ctk.CTkFrame(card, fg_color="transparent")
                status_row.pack(fill="x", padx=14, pady=(6, 0))
                ctk.CTkLabel(status_row, text="Status:", font=FONT_SMALL,
                             text_color=TEXT_MUTED).pack(side="left")
                ctk.CTkLabel(status_row, text=f"● {vstatus}",
                             font=FONT_SMALL, text_color=vs_color).pack(
                    side="left", padx=8)
                new_status = "Closed" if vstatus == "Open" else "Open"
                ctk.CTkButton(status_row, text=f"Mark {new_status}",
                              height=26, width=100, corner_radius=BTN_RADIUS,
                              fg_color=SEV_COLORS["Low"]["bg"] if new_status == "Closed"
                              else SEV_COLORS["Critical"]["bg"],
                              hover_color=CARD_BG,
                              text_color=SEV_COLORS["Low"]["fg"] if new_status == "Closed"
                              else SEV_COLORS["Critical"]["fg"],
                              font=FONT_SMALL,
                              command=lambda vid=v["id"], s=new_status:
                              self._toggle_vuln_status(vid, s)).pack(
                    side="left", padx=4)

            # Quick detail rows
            for label, val in [
                ("Affected",     v.get("affected", "")),
                ("Description",  truncate(v.get("description", ""), 120)),
                ("Found At",     format_dt(v.get("found_at", ""))),
            ]:
                if val:
                    r = ctk.CTkFrame(card, fg_color="transparent")
                    r.pack(fill="x", padx=14, pady=2)
                    ctk.CTkLabel(r, text=f"{label}:", font=FONT_SMALL,
                                 text_color=TEXT_MUTED, width=100,
                                 anchor="w").pack(side="left")
                    ctk.CTkLabel(r, text=str(val), font=FONT_SMALL,
                                 text_color=TEXT_PRIMARY, anchor="w",
                                 wraplength=700).pack(side="left")

            # POC image count indicator (no preview in list — see detail view)
            if poc_paths:
                ctk.CTkLabel(card,
                             text=f"📸  {len(poc_paths)} POC image(s) attached",
                             font=FONT_SMALL, text_color=ACCENT).pack(
                    anchor="w", padx=14, pady=(4, 0))

            ctk.CTkButton(card, text="View Full Details + Images →",
                          height=28, corner_radius=6,
                          fg_color="transparent", text_color=ACCENT,
                          hover_color=CARD_BG, font=FONT_SMALL,
                          command=lambda vv=v: self._show_single_vuln(vv)).pack(
                anchor="e", padx=14, pady=(4, 10))

    def _toggle_vuln_status(self, vuln_db_id: int, new_status: str):
        update_vulnerability_status(vuln_db_id, new_status)
        self._show_vulnerabilities()

    # ── Single vulnerability detail ────────────────────────────────────────────

    def _show_single_vuln(self, v):
        self._clear_content()
        sev      = v.get("severity", "Low")
        vstatus  = v.get("vuln_status", "Open")
        poc_paths = self._load_poc(v)

        self._section_label(f"{severity_icon(sev)}  {v['vuln_id']} — {v['title']}")

        def row(label, val, mono=False):
            if val is None or str(val).strip() in ("", "NA"):
                return
            r = ctk.CTkFrame(self.content, fg_color=PANEL_BG, corner_radius=8)
            r.pack(fill="x", padx=20, pady=3)
            ctk.CTkLabel(r, text=label, font=FONT_SMALL,
                         text_color=TEXT_MUTED, width=165, anchor="w").pack(
                side="left", padx=(14, 4), pady=8)
            ctk.CTkLabel(r, text=str(val),
                         font=FONT_MONO if mono else FONT_BODY,
                         text_color=TEXT_PRIMARY, anchor="w",
                         wraplength=700, justify="left").pack(
                side="left", fill="x", expand=True, padx=(4, 14))

        vs_color = SEV_COLORS["Low"]["fg"] if vstatus == "Closed" \
            else SEV_COLORS["Critical"]["fg"]

        row("Vulnerability ID",   v.get("vuln_id", ""))
        row("Severity",           f"{severity_icon(sev)} {sev}")
        row("Status",             f"● {vstatus}")
        row("CVSS Score",         str(v.get("cvss_score", "")))
        row("CVSS Vector",        v.get("cvss_vector", ""), mono=True)
        row("Affected",           v.get("affected", ""))
        row("Description",        v.get("description", ""))
        row("Steps to Reproduce", v.get("steps_to_reproduce", ""), mono=True)
        row("Impact",             v.get("impact", ""))
        row("Recommendations",    v.get("recommendations", ""))
        row("Reference",          v.get("reference", ""))
        row("Found At",           format_dt(v.get("found_at", "")))

        # ── POC images ──
        if poc_paths:
            self._section_label("📸  POC Screenshots / Evidence")
            self._display_poc_images(poc_paths)
        else:
            ctk.CTkLabel(self.content,
                         text="No POC images attached to this vulnerability.",
                         font=FONT_SMALL, text_color=TEXT_MUTED).pack(
                padx=20, pady=6, anchor="w")

        ctk.CTkButton(self.content,
                      text="← Back to All Vulnerabilities",
                      height=BTN_HEIGHT, corner_radius=BTN_RADIUS,
                      fg_color="transparent", border_color=BORDER, border_width=1,
                      text_color=TEXT_MUTED, hover_color=CARD_BG,
                      font=FONT_BODY, command=self._show_vulnerabilities).pack(
            padx=20, pady=16, anchor="w")

    # ── POC image display ──────────────────────────────────────────────────────

    def _load_poc(self, v: dict) -> list:
        try:
            return json.loads(v.get("poc_images", "[]") or "[]")
        except Exception:
            return []

    def _display_poc_images(self, poc_paths: list):
        """Show POC images as filename list only (no preview rendering)."""
        for img_path in poc_paths:
            filename = os.path.basename(img_path) if img_path else "Unknown"
            exists   = img_path and os.path.exists(img_path)

            card = ctk.CTkFrame(self.content, fg_color=PANEL_BG,
                                corner_radius=8)
            card.pack(fill="x", padx=20, pady=3)

            icon  = "📎" if exists else "⚠️"
            color = TEXT_PRIMARY if exists else SEV_COLORS["Medium"]["fg"]
            note  = "" if exists else "  (file not found)"

            ctk.CTkLabel(card,
                         text=f"{icon}  {filename}{note}",
                         font=FONT_BODY,
                         text_color=color,
                         anchor="w").pack(padx=14, pady=10, anchor="w")

    # ── Removed vulns ──────────────────────────────────────────────────────────

    def _show_removed(self):
        self._clear_content()
        self._section_label("🗂️  Removed Vulnerabilities")
        removed = get_removed_vulnerabilities(self.project["id"])
        if not removed:
            ctk.CTkLabel(self.content,
                         text="No removed vulnerabilities for this project.",
                         font=FONT_BODY, text_color=TEXT_MUTED).pack(
                padx=20, pady=20, anchor="w")
            return
        for v in removed:
            sev     = v.get("severity", "Low")
            sev_col = SEV_COLORS.get(sev, {})
            card = ctk.CTkFrame(self.content, fg_color=PANEL_BG,
                                corner_radius=CARD_RADIUS)
            card.pack(fill="x", padx=20, pady=5)
            ctk.CTkLabel(card,
                         text=f"{severity_icon(sev)}  {v['original_vuln_id']}  —  {v['title']}",
                         font=FONT_SUBHEAD,
                         text_color=sev_col.get("fg", TEXT_PRIMARY)).pack(
                anchor="w", padx=14, pady=(10, 2))
            ctk.CTkLabel(card,
                         text=f"Removed: {format_dt(v['removed_at'])}  |  By: {v.get('removed_by','N/A')}",
                         font=FONT_SMALL, text_color=TEXT_MUTED).pack(
                anchor="w", padx=14, pady=(0, 10))

        ctk.CTkButton(self.content, text="💾  Save to TXT File",
                      height=BTN_HEIGHT, corner_radius=BTN_RADIUS,
                      fg_color=CARD_BG, hover_color=BORDER,
                      text_color=TEXT_PRIMARY, font=FONT_BODY,
                      command=self._save_removed_txt).pack(
            padx=20, pady=12, anchor="w")

    def _save_removed_txt(self):
        p    = self.project
        path = save_removed_to_txt(p["id"], p["project_name"], p["client_name"])
        if path:
            messagebox.showinfo("Saved", f"Saved to:\n{path}", parent=self)
            open_folder(os.path.dirname(path))

    def _show_hold_reason(self):
        self._clear_content()
        self._section_label("⏸️  Hold Reason")
        reason = self.project.get("hold_reason", "No reason provided.")
        c = ctk.CTkFrame(self.content, fg_color=PANEL_BG, corner_radius=CARD_RADIUS)
        c.pack(fill="x", padx=20, pady=8)
        ctk.CTkLabel(c, text=reason, font=FONT_BODY,
                     text_color=TEXT_PRIMARY, wraplength=800,
                     justify="left").pack(padx=16, pady=14, anchor="w")

    # ── Actions ───────────────────────────────────────────────────────────────

    def _add_vulnerability(self):
        if not self.project.get("testing_started", 0):
            messagebox.showwarning("Not Started",
                "Click 'Start Pentest' before adding vulnerabilities.", parent=self)
            return
        VulnFormWindow(self, self.project, self.current_user,
                       on_success=self._on_vuln_change)

    def _on_vuln_change(self):
        """Called after add/remove — renumber then refresh."""
        renumber_vulnerabilities(self.project["id"])
        self._refresh()

    def _edit_vulnerability(self):
        vulns = get_vulnerabilities(self.project["id"])
        if not vulns:
            messagebox.showinfo("Empty", "No vulnerabilities to edit.", parent=self)
            return
        self._pick_vuln_dialog(vulns, action="edit")

    def _remove_vulnerability(self):
        vulns = get_vulnerabilities(self.project["id"])
        if not vulns:
            messagebox.showinfo("Empty", "No vulnerabilities to remove.", parent=self)
            return
        self._pick_vuln_dialog(vulns, action="remove")

    def _pick_vuln_dialog(self, vulns, action):
        pick = ctk.CTkToplevel(self)
        pick.title("Select Vulnerability")
        pick.geometry("600x480")
        pick.configure(fg_color=DARK_BG)
        pick.grab_set()

        ctk.CTkLabel(pick,
                     text=f"{'Edit' if action == 'edit' else 'Remove'} Vulnerability",
                     font=FONT_HEADING, text_color=TEXT_PRIMARY).pack(
            padx=20, pady=(18, 4))

        scroll = ctk.CTkScrollableFrame(pick, fg_color=DARK_BG)
        scroll.pack(fill="both", expand=True, padx=20)

        selected = {"vuln": None}
        buttons  = []

        def select(v, idx):
            selected["vuln"] = v
            for i, b in enumerate(buttons):
                b.configure(
                    fg_color=ACCENT if i == idx else "transparent",
                    text_color=WHITE if i == idx else
                    SEV_COLORS.get(vulns[i].get("severity","Low"),{}).get("fg",TEXT_PRIMARY))

        for i, v in enumerate(vulns):
            sev     = v.get("severity", "Low")
            sev_col = SEV_COLORS.get(sev, {})
            btn = ctk.CTkButton(scroll,
                                text=f"{i+1}.  {severity_icon(sev)}  {v['vuln_id']}  —  "
                                     f"{v['title']}  [{sev} | {v['cvss_score']}]",
                                height=40, corner_radius=BTN_RADIUS,
                                fg_color="transparent", hover_color=CARD_BG,
                                text_color=sev_col.get("fg", TEXT_PRIMARY),
                                font=FONT_BODY, anchor="w",
                                command=lambda vv=v, idx=i: select(vv, idx))
            btn.pack(fill="x", pady=3)
            buttons.append(btn)

        def confirm():
            v = selected["vuln"]
            if not v:
                messagebox.showwarning("Select", "Please select a vulnerability.", parent=pick)
                return
            pick.destroy()
            if action == "edit":
                VulnFormWindow(self, self.project, self.current_user,
                               existing_vuln=v, on_success=self._on_vuln_change)
            elif action == "remove":
                ok = messagebox.askyesno("Confirm",
                    f"Remove '{v['title']}'?\nIt will be saved to the removed log.",
                    parent=self)
                if ok:
                    remove_vulnerability(v["id"], self.current_user["email"])
                    save_removed_to_txt(self.project["id"],
                                       self.project["project_name"],
                                       self.project["client_name"])
                    self._on_vuln_change()

        ctk.CTkButton(pick, text="Confirm", height=BTN_HEIGHT,
                      corner_radius=BTN_RADIUS, fg_color=ACCENT,
                      hover_color=ACCENT_HOVER, font=FONT_BTN,
                      command=confirm).pack(padx=20, pady=12, fill="x")

    def _start_pentest(self):
        ok = messagebox.askyesno("Start Pentest",
            f"Start pentest on '{self.project['project_name']}'?\n\n"
            f"Status → Running. You can then add vulnerabilities.",
            parent=self)
        if ok:
            update_project_status(self.project["id"], "Running")
            set_project_testing_started(self.project["id"])
            # Notify assigned admin that testing has started
            assigned = self.project.get("assigned_admin_email") or self.project.get("manager_email","")
            if assigned:
                from database.db_manager import create_notification
                create_notification(
                    assigned,
                    "▶️  Pentest Started",
                    f"'{self.project['project_name']}' — {self.project['pentester_name']} "
                    f"has started the pentest (status: Running).",
                    notif_type="info", link_type="project", link_id=self.project["id"]
                )
            messagebox.showinfo("✅  Pentest Started",
                "Pentest is Running!\n\nYou can now add vulnerabilities.",
                parent=self)
            self._refresh()

    def _put_on_hold(self):
        win = ctk.CTkToplevel(self)
        win.title("Put on Hold")
        win.geometry("500x290")
        win.configure(fg_color=DARK_BG)
        win.grab_set()
        ctk.CTkLabel(win, text="Reason for Hold",
                     font=FONT_HEADING, text_color=TEXT_PRIMARY).pack(
            padx=20, pady=(18, 8))
        txt = ctk.CTkTextbox(win, height=120, fg_color=CARD_BG,
                             border_color=BORDER, text_color=TEXT_PRIMARY,
                             font=FONT_BODY)
        txt.pack(padx=20, fill="x")

        def confirm():
            reason = txt.get("1.0", "end").strip()
            if not reason:
                messagebox.showwarning("Required", "Enter a reason.", parent=win)
                return
            update_project_status(self.project["id"], "Hold",
                                  extra={"hold_reason": reason})
            win.destroy()
            self._refresh()

        ctk.CTkButton(win, text="Confirm Hold", height=BTN_HEIGHT,
                      corner_radius=BTN_RADIUS,
                      fg_color=SEV_COLORS["Critical"]["bg"], hover_color=CARD_BG,
                      text_color=SEV_COLORS["Critical"]["fg"],
                      font=FONT_BTN, command=confirm).pack(
            padx=20, pady=12, fill="x")

    def _restart_project(self):
        ok = messagebox.askyesno("Restart", "Restart project? Status → Running.", parent=self)
        if ok:
            update_project_status(self.project["id"], "Running",
                                  extra={"hold_reason": None})
            self._refresh()

    def _finish_project(self):
        vulns = get_vulnerabilities(self.project["id"])
        confirm_msg = (
            f"Finish project and submit for Admin Review?\n\n"
            f"{len(vulns)} vulnerability(ies) recorded."
            if vulns else
            "No vulnerabilities added. Finish anyway?"
        )
        if not messagebox.askyesno("Finish Project", confirm_msg, parent=self):
            return

        sum_win = ctk.CTkToplevel(self)
        sum_win.title("Executive Summary")
        sum_win.geometry("640x400")
        sum_win.configure(fg_color=DARK_BG)
        sum_win.grab_set()

        ctk.CTkLabel(sum_win, text="Write Executive Summary",
                     font=FONT_HEADING, text_color=TEXT_PRIMARY).pack(
            padx=20, pady=(18, 4))
        ctk.CTkLabel(sum_win,
                     text="Summarise findings for the admin review.",
                     font=FONT_SMALL, text_color=TEXT_MUTED).pack(padx=20, pady=(0, 8))
        txt = ctk.CTkTextbox(sum_win, height=200, fg_color=CARD_BG,
                             border_color=BORDER, text_color=TEXT_PRIMARY,
                             font=FONT_BODY, wrap="word")
        txt.pack(padx=20, fill="x")

        err_lbl = ctk.CTkLabel(sum_win, text="", font=FONT_SMALL,
                               text_color=SEV_COLORS["Critical"]["fg"])
        err_lbl.pack(pady=4)

        def submit():
            summary = txt.get("1.0", "end").strip()
            if not summary:
                err_lbl.configure(text="Executive summary is required.")
                return
            update_project_field(self.project["id"], "executive_summary", summary)
            update_project_status(self.project["id"], "Admin Review")
            # Notify assigned admin
            assigned = self.project.get("assigned_admin_email") or self.project.get("manager_email","")
            if assigned:
                from database.db_manager import create_notification
                create_notification(
                    assigned,
                    "📝  Project Ready for Review",
                    f"'{self.project['project_name']}' by {self.project['pentester_name']} "
                    f"has been submitted for Admin Review.",
                    notif_type="request", link_type="project", link_id=self.project["id"]
                )
            sum_win.destroy()
            self._refresh()
            messagebox.showinfo("Submitted",
                "Project submitted for Admin Review.",
                parent=self)

        ctk.CTkButton(sum_win, text="Submit for Admin Review",
                      height=BTN_HEIGHT + 2, corner_radius=BTN_RADIUS,
                      fg_color=ACCENT, hover_color=ACCENT_HOVER,
                      font=FONT_BTN, command=submit).pack(
            padx=20, pady=8, fill="x")

    def _generate_reports(self):
        status = self.project.get("status", "")
        if status not in ("Admin Review", "Completed", "Running"):
            messagebox.showwarning("Not Available",
                "⚠️  Project must be Running, in Admin Review, or Completed to generate reports.",
                parent=self)
            return

        if status == "Running":
            if not messagebox.askyesno("Partial Report",
                "⚠️  Project is still in progress. Generate a partial report now?",
                parent=self):
                return

        name_win = ctk.CTkToplevel(self)
        name_win.title("Report File Name")
        name_win.geometry("480x200")
        name_win.configure(fg_color=DARK_BG)
        name_win.grab_set()

        ctk.CTkLabel(name_win, text="Report Name",
                     font=FONT_HEADING, text_color=TEXT_PRIMARY).pack(
            padx=20, pady=(18, 4))
        ctk.CTkLabel(name_win, text="Enter a name (without extension):",
                     font=FONT_SMALL, text_color=TEXT_MUTED).pack(
            padx=20, pady=(0, 8))
        entry = ctk.CTkEntry(name_win, height=ENTRY_HEIGHT,
                             placeholder_text=f"{self.project['project_name']}_Report",
                             fg_color=CARD_BG, border_color=BORDER,
                             text_color=TEXT_PRIMARY)
        entry.pack(padx=20, fill="x")
        err_lbl = ctk.CTkLabel(name_win, text="", font=FONT_SMALL,
                               text_color=SEV_COLORS["Critical"]["fg"])
        err_lbl.pack(pady=4)

        def generate():
            rname = entry.get().strip() or f"{self.project['project_name']}_Report"
            try:
                result = generate_reports(self.project["id"], rname)
                name_win.destroy()
                messagebox.showinfo("✅  Reports Generated",
                    f"Saved to:\n{result['folder']}\n\n"
                    f"📄 {os.path.basename(result['pdf'])}\n"
                    f"📝 {os.path.basename(result['docx'])}",
                    parent=self)
                open_folder(result["folder"])
            except Exception as e:
                err_lbl.configure(text=f"Error: {e}")

        ctk.CTkButton(name_win, text="Generate PDF + Word",
                      height=BTN_HEIGHT + 2, corner_radius=BTN_RADIUS,
                      fg_color=ACCENT, hover_color=ACCENT_HOVER,
                      font=FONT_BTN, command=generate).pack(
            padx=20, pady=8, fill="x")
