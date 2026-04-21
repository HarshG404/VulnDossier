"""
vuln_form_window.py — VulnDossier Add/Edit Vulnerability.
  • Built-in CVSS v3.1 calculator (select metrics → auto-calculates score & vector)
  • Multiline textbox for steps to reproduce (no \\n needed)
  • POC image upload (multiple images stored per vulnerability)
  • Open/Closed status
"""
import os
import json
import customtkinter as ctk
from tkinter import messagebox, filedialog
from ui.theme import *
from database.db_manager import (
    add_vulnerability, update_vulnerability_full,
    get_next_vuln_id, update_vulnerability_poc_images
)

SEVERITY_OPTIONS = ["Critical", "High", "Medium", "Low", "Informational"]

# ── CVSS v3.1 metric definitions ──────────────────────────────────────────────
CVSS_METRICS = {
    "Attack Vector (AV)": {
        "key": "AV",
        "options": [
            ("Network (N)",   "N", 0.85),
            ("Adjacent (A)",  "A", 0.62),
            ("Local (L)",     "L", 0.55),
            ("Physical (P)",  "P", 0.20),
        ]
    },
    "Attack Complexity (AC)": {
        "key": "AC",
        "options": [
            ("Low (L)",  "L", 0.77),
            ("High (H)", "H", 0.44),
        ]
    },
    "Privileges Required (PR)": {
        "key": "PR",
        "options": [
            ("None (N)",   "N", 0.85),
            ("Low (L)",    "L", 0.62),
            ("High (H)",   "H", 0.27),
        ]
    },
    "User Interaction (UI)": {
        "key": "UI",
        "options": [
            ("None (N)",     "N", 0.85),
            ("Required (R)", "R", 0.62),
        ]
    },
    "Scope (S)": {
        "key": "S",
        "options": [
            ("Unchanged (U)", "U", None),
            ("Changed (C)",   "C", None),
        ]
    },
    "Confidentiality (C)": {
        "key": "C",
        "options": [
            ("High (H)",   "H", 0.56),
            ("Low (L)",    "L", 0.22),
            ("None (N)",   "N", 0.00),
        ]
    },
    "Integrity (I)": {
        "key": "I",
        "options": [
            ("High (H)",   "H", 0.56),
            ("Low (L)",    "L", 0.22),
            ("None (N)",   "N", 0.00),
        ]
    },
    "Availability (A)": {
        "key": "A",
        "options": [
            ("High (H)",   "H", 0.56),
            ("Low (L)",    "L", 0.22),
            ("None (N)",   "N", 0.00),
        ]
    },
}


def _compute_cvss(selections: dict) -> tuple:
    """
    Compute CVSS v3.1 base score from metric selections.
    Returns (score: float, vector: str, severity: str)
    """
    try:
        av  = {"N":0.85, "A":0.62, "L":0.55, "P":0.20}[selections.get("AV","N")]
        ac  = {"L":0.77, "H":0.44}[selections.get("AC","L")]
        ui  = {"N":0.85, "R":0.62}[selections.get("UI","N")]
        s   = selections.get("S","U")
        c_  = {"H":0.56, "L":0.22, "N":0.00}[selections.get("C","H")]
        i_  = {"H":0.56, "L":0.22, "N":0.00}[selections.get("I","H")]
        a_  = {"H":0.56, "L":0.22, "N":0.00}[selections.get("A","H")]

        pr_vals = {"U": {"N":0.85,"L":0.62,"H":0.27},
                   "C": {"N":0.85,"L":0.68,"H":0.50}}
        pr = pr_vals[s][selections.get("PR","N")]

        iss = 1 - (1-c_)*(1-i_)*(1-a_)
        if s == "U":
            scope_score = 6.42 * iss
        else:
            scope_score = 7.52*(iss-0.029) - 3.25*((iss-0.02)**15)

        exploit = 8.22 * av * ac * pr * ui

        if scope_score <= 0:
            base = 0.0
        elif s == "U":
            base = min(scope_score + exploit, 10)
        else:
            base = min(1.08*(scope_score + exploit), 10)

        # Round up to 1 decimal
        import math
        score = math.ceil(base * 10) / 10

        vector = (f"CVSS:3.1/AV:{selections.get('AV','N')}/AC:{selections.get('AC','L')}"
                  f"/PR:{selections.get('PR','N')}/UI:{selections.get('UI','N')}"
                  f"/S:{s}/C:{selections.get('C','H')}"
                  f"/I:{selections.get('I','H')}/A:{selections.get('A','H')}")

        if score >= 9.0:   sev = "Critical"
        elif score >= 7.0: sev = "High"
        elif score >= 4.0: sev = "Medium"
        elif score > 0.0:  sev = "Low"
        else:              sev = "Informational"

        return round(score, 1), vector, sev
    except Exception:
        return 0.0, "", "Informational"


class VulnFormWindow(ctk.CTkToplevel):
    def __init__(self, parent, project, current_user,
                 existing_vuln=None, on_success=None):
        super().__init__(parent)
        self.project      = project
        self.current_user = current_user
        self.existing     = existing_vuln
        self.on_success   = on_success
        self.is_edit      = existing_vuln is not None
        self._poc_images  = []  # list of absolute paths

        # Load existing poc images
        if self.is_edit:
            try:
                self._poc_images = json.loads(
                    existing_vuln.get("poc_images", "[]") or "[]")
            except Exception:
                self._poc_images = []

        # CVSS metric vars — default to Critical scenario
        self._cvss_vars = {}

        title = "Edit Vulnerability" if self.is_edit else "Add Vulnerability"
        self.title(title)
        self.geometry("720x940")
        self.resizable(True, True)
        self.configure(fg_color=DARK_BG)
        self.grab_set()
        self._build()

    def _build(self):
        hdr = ctk.CTkFrame(self, fg_color=PANEL_BG, corner_radius=0)
        hdr.pack(fill="x")
        icon  = "✏️" if self.is_edit else "➕"
        title = "Edit Vulnerability" if self.is_edit else "Add New Vulnerability"
        ctk.CTkLabel(hdr, text=f"{icon}  {title}",
                     font=FONT_HEADING, text_color=TEXT_PRIMARY).pack(
            side="left", padx=20, pady=14)
        vuln_id = self.existing["vuln_id"] if self.is_edit else get_next_vuln_id(self.project["id"])
        ctk.CTkLabel(hdr, text=f"ID: {vuln_id}",
                     font=FONT_BODY, text_color=ACCENT).pack(side="right", padx=20)

        scroll = ctk.CTkScrollableFrame(self, fg_color=DARK_BG)
        scroll.pack(fill="both", expand=True)

        ev = self.existing or {}

        # ── Section helper ────────────────────────────────────────────────────
        def section(title):
            f = ctk.CTkFrame(scroll, fg_color=PANEL_BG, corner_radius=CARD_RADIUS)
            f.pack(fill="x", padx=20, pady=(12, 0))
            ctk.CTkLabel(f, text=title, font=FONT_SUBHEAD,
                         text_color=ACCENT).pack(anchor="w", padx=16, pady=(12, 4))
            return f

        def lbl(frame, text, req=True):
            ctk.CTkLabel(frame, text=f"{text}{' *' if req else ''}",
                         font=FONT_SMALL, text_color=TEXT_MUTED, anchor="w").pack(
                padx=16, pady=(8, 2), fill="x")

        def entry(frame, val="", ph=""):
            e = ctk.CTkEntry(frame, height=ENTRY_HEIGHT, placeholder_text=ph,
                             fg_color=CARD_BG, border_color=BORDER,
                             text_color=TEXT_PRIMARY)
            e.pack(padx=16, fill="x")
            if val:
                e.insert(0, str(val))
            return e

        def textbox(frame, height=80, val=""):
            t = ctk.CTkTextbox(frame, height=height, fg_color=CARD_BG,
                               border_color=BORDER, text_color=TEXT_PRIMARY,
                               font=FONT_BODY, wrap="word")
            t.pack(padx=16, fill="x")
            if val:
                t.insert("1.0", val)
            return t

        # ── Basic Info ────────────────────────────────────────────────────────
        s1 = section("Basic Information")
        lbl(s1, "Vulnerability Title")
        self.e_title = entry(s1, ev.get("title", ""),
                             "e.g. SQL Injection — Login Endpoint")

        lbl(s1, "Affected Area / Component")
        self.e_affected = entry(s1, ev.get("affected", ""),
                                "e.g. POST /api/v1/auth/login")
        ctk.CTkLabel(s1, text="", height=4).pack()

        # ── CVSS v3.1 Calculator ──────────────────────────────────────────────
        s2 = section("CVSS v3.1 Calculator")
        ctk.CTkLabel(s2,
                     text="Select each metric — score and vector are calculated automatically.",
                     font=FONT_SMALL, text_color=TEXT_MUTED).pack(
            anchor="w", padx=16, pady=(0, 8))

        # Parse existing vector to pre-select
        existing_vector_sel = {}
        existing_vector = ev.get("cvss_vector", "")
        if existing_vector and existing_vector.startswith("CVSS:3.1/"):
            for part in existing_vector.split("/")[1:]:
                if ":" in part:
                    k, v2 = part.split(":", 1)
                    existing_vector_sel[k] = v2

        for metric_name, metric_info in CVSS_METRICS.items():
            key     = metric_info["key"]
            options = metric_info["options"]

            m_row = ctk.CTkFrame(s2, fg_color=CARD_BG, corner_radius=8)
            m_row.pack(fill="x", padx=16, pady=3)
            ctk.CTkLabel(m_row, text=metric_name, font=FONT_SMALL,
                         text_color=TEXT_MUTED, width=200, anchor="w").pack(
                side="left", padx=12, pady=8)

            # Default: first option, or from existing vector
            default_abbr = existing_vector_sel.get(key, options[0][1])
            var = ctk.StringVar(value=default_abbr)
            self._cvss_vars[key] = var

            for label, abbr, _ in options:
                ctk.CTkRadioButton(
                    m_row, text=label, variable=var, value=abbr,
                    text_color=TEXT_PRIMARY, fg_color=ACCENT,
                    command=self._update_cvss_display
                ).pack(side="left", padx=8, pady=8)

        # Score display
        score_row = ctk.CTkFrame(s2, fg_color=CARD_BG, corner_radius=8)
        score_row.pack(fill="x", padx=16, pady=(8, 4))
        ctk.CTkLabel(score_row, text="Calculated Score:",
                     font=FONT_BODY, text_color=TEXT_MUTED).pack(
            side="left", padx=14, pady=10)
        self.score_lbl = ctk.CTkLabel(score_row, text="—",
                                       font=("Segoe UI", 20, "bold"),
                                       text_color=ACCENT)
        self.score_lbl.pack(side="left", padx=8)
        self.sev_lbl = ctk.CTkLabel(score_row, text="",
                                     font=FONT_SUBHEAD, text_color=TEXT_MUTED)
        self.sev_lbl.pack(side="left", padx=4)

        ctk.CTkLabel(s2, text="CVSS Vector:", font=FONT_SMALL,
                     text_color=TEXT_MUTED, anchor="w").pack(
            padx=16, pady=(2, 2), fill="x")
        self.vector_lbl = ctk.CTkLabel(s2, text="—", font=FONT_MONO,
                                        text_color=TEXT_MUTED, anchor="w",
                                        wraplength=640)
        self.vector_lbl.pack(padx=16, pady=(0, 12), anchor="w")

        # Trigger initial calculation
        self._update_cvss_display()

        # ── Vulnerability Details ─────────────────────────────────────────────
        s3 = section("Vulnerability Details")

        lbl(s3, "Description")
        self.e_desc = textbox(s3, height=90, val=ev.get("description", ""))

        lbl(s3, "Impact")
        self.e_impact = textbox(s3, height=70, val=ev.get("impact", ""))

        lbl(s3, "Recommendations")
        self.e_rec = textbox(s3, height=70, val=ev.get("recommendations", ""))

        lbl(s3, "Steps to Reproduce (type normally — press Enter for new lines, no \\n needed)")
        self.e_steps = textbox(s3, height=110,
                               val=ev.get("steps_to_reproduce", ""))

        lbl(s3, "Reference (URL, CVE number, or leave as NA)", req=False)
        self.e_ref = entry(s3, ev.get("reference", ""),
                           "https://owasp.org/... or CVE-2026-XXXX or NA")
        ctk.CTkLabel(s3, text="", height=4).pack()

        # ── POC Images ────────────────────────────────────────────────────────
        s4 = section("📸  POC Screenshots / Evidence")
        ctk.CTkLabel(s4,
                     text="Attach screenshot images (PNG, JPG, GIF). They will be embedded in the report.",
                     font=FONT_SMALL, text_color=TEXT_MUTED).pack(
            anchor="w", padx=16, pady=(0, 8))

        self.poc_list_frame = ctk.CTkFrame(s4, fg_color=CARD_BG, corner_radius=8)
        self.poc_list_frame.pack(fill="x", padx=16, pady=(0, 8))
        self._render_poc_list()

        ctk.CTkButton(s4, text="➕  Add Screenshot / POC Image",
                      height=BTN_HEIGHT - 4, corner_radius=BTN_RADIUS,
                      fg_color=CARD_BG, hover_color=BORDER,
                      text_color=ACCENT, font=FONT_BODY,
                      command=self._browse_poc).pack(
            padx=16, fill="x", pady=(0, 12))

        # ── Submit ────────────────────────────────────────────────────────────
        self.err_lbl = ctk.CTkLabel(scroll, text="", font=FONT_SMALL,
                                    text_color=SEV_COLORS["Critical"]["fg"],
                                    wraplength=620)
        self.err_lbl.pack(pady=(10, 4))

        btn_text = "Update Vulnerability" if self.is_edit else "Add Vulnerability"
        ctk.CTkButton(scroll, text=btn_text, height=BTN_HEIGHT + 4,
                      corner_radius=BTN_RADIUS, fg_color=ACCENT,
                      hover_color=ACCENT_HOVER, font=FONT_BTN,
                      command=self._submit).pack(padx=20, fill="x")
        ctk.CTkButton(scroll, text="Cancel", height=BTN_HEIGHT,
                      corner_radius=BTN_RADIUS, fg_color="transparent",
                      border_color=BORDER, border_width=1,
                      text_color=TEXT_MUTED, hover_color=CARD_BG,
                      font=FONT_BODY, command=self.destroy).pack(
            padx=20, pady=(8, 20), fill="x")

    # ── CVSS Calculator ───────────────────────────────────────────────────────

    def _update_cvss_display(self):
        selections = {k: v.get() for k, v in self._cvss_vars.items()}
        score, vector, sev = _compute_cvss(selections)

        sev_col = SEV_COLORS.get(sev, {}).get("fg", TEXT_MUTED)
        self.score_lbl.configure(text=str(score), text_color=sev_col)
        self.sev_lbl.configure(text=sev, text_color=sev_col)
        self.vector_lbl.configure(text=vector)

    def _get_cvss_values(self):
        """Return (score, vector, severity) from current calculator state."""
        selections = {k: v.get() for k, v in self._cvss_vars.items()}
        return _compute_cvss(selections)

    # ── POC Images ───────────────────────────────────────────────────────────

    def _render_poc_list(self):
        for w in self.poc_list_frame.winfo_children():
            w.destroy()
        if not self._poc_images:
            ctk.CTkLabel(self.poc_list_frame,
                         text="No images attached yet.",
                         font=FONT_SMALL, text_color=TEXT_MUTED).pack(
                padx=12, pady=10)
        else:
            for i, path in enumerate(self._poc_images):
                row = ctk.CTkFrame(self.poc_list_frame, fg_color="transparent")
                row.pack(fill="x", padx=12, pady=3)
                ctk.CTkLabel(row,
                             text=f"📎  {os.path.basename(path)}",
                             font=FONT_SMALL, text_color=TEXT_PRIMARY,
                             anchor="w").pack(side="left", fill="x", expand=True)
                ctk.CTkButton(row, text="✕", width=30, height=26,
                              corner_radius=BTN_RADIUS,
                              fg_color="transparent",
                              hover_color=SEV_COLORS["Critical"]["bg"],
                              text_color=SEV_COLORS["Critical"]["fg"],
                              font=FONT_SMALL,
                              command=lambda idx=i: self._remove_poc(idx)).pack(side="right")

    def _browse_poc(self):
        paths = filedialog.askopenfilenames(
            parent=self,
            title="Select POC Screenshot(s)",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.gif *.bmp *.webp"),
                       ("All files", "*.*")]
        )
        if paths:
            for p in paths:
                if p not in self._poc_images:
                    self._poc_images.append(p)
            self._render_poc_list()

    def _remove_poc(self, index):
        if 0 <= index < len(self._poc_images):
            self._poc_images.pop(index)
            self._render_poc_list()

    # ── Submit ────────────────────────────────────────────────────────────────

    def _g(self, w):
        try:
            return w.get("1.0", "end").strip()
        except Exception:
            return w.get().strip()

    def _submit(self):
        title    = self._g(self.e_title)
        affected = self._g(self.e_affected)
        desc     = self._g(self.e_desc)
        impact   = self._g(self.e_impact)
        rec      = self._g(self.e_rec)
        steps    = self._g(self.e_steps)
        ref      = self._g(self.e_ref) or "NA"

        if not all([title, affected, desc, rec]):
            self.err_lbl.configure(
                text="Title, Affected Area, Description and Recommendations are required.")
            return

        score, vector, sev = self._get_cvss_values()

        images_json = json.dumps(self._poc_images)

        data = {
            "project_id":         self.project["id"],
            "vuln_id":            (self.existing["vuln_id"] if self.is_edit
                                   else get_next_vuln_id(self.project["id"])),
            "title":              title,
            "severity":           sev,
            "cvss_score":         score,
            "cvss_vector":        vector,
            "affected":           affected,
            "description":        desc,
            "impact":             impact,
            "recommendations":    rec,
            "reference":          ref,
            "steps_to_reproduce": steps,
        }

        if self.is_edit:
            update_vulnerability_full(self.existing["id"], data)
            update_vulnerability_poc_images(self.existing["id"], images_json)
            msg = f"✅ '{title}' updated."
        else:
            new_id = add_vulnerability(data)
            update_vulnerability_poc_images(new_id, images_json)
            msg = f"✅ '{title}' added successfully."

        messagebox.showinfo("Success", msg, parent=self)
        if self.on_success:
            self.on_success()
        self.destroy()
