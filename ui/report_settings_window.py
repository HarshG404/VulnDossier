"""
report_settings_window.py — GUI for admins to configure report branding and layout.
Accessible from the dashboard. Changes saved to config/report_config.json.
"""
import os
import customtkinter as ctk
from tkinter import messagebox, filedialog, colorchooser
from ui.theme import *
from config.config_manager import load_config, save_config


class ReportSettingsWindow(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Report Settings — Admin Configuration")
        self.geometry("780x860")
        self.resizable(True, True)
        self.configure(fg_color=DARK_BG)
        self.grab_set()
        self.config = load_config()
        self._build()

    # ─────────────────────────────────────────────────────────────────────────

    def _build(self):
        # Header
        hdr = ctk.CTkFrame(self, fg_color=PANEL_BG, corner_radius=0)
        hdr.pack(fill="x")
        ctk.CTkLabel(hdr, text="⚙️  Report Settings",
                     font=FONT_HEADING, text_color=TEXT_PRIMARY).pack(side="left", padx=20, pady=14)
        ctk.CTkLabel(hdr, text="Changes apply to all future report generations",
                     font=FONT_SMALL, text_color=TEXT_MUTED).pack(side="right", padx=20)

        # Tabs
        self.tab_view = ctk.CTkTabview(self, fg_color=DARK_BG,
                                        segmented_button_fg_color=PANEL_BG,
                                        segmented_button_selected_color=ACCENT,
                                        segmented_button_selected_hover_color=ACCENT_HOVER,
                                        segmented_button_unselected_color=PANEL_BG,
                                        segmented_button_unselected_hover_color=CARD_BG,
                                        text_color=TEXT_PRIMARY)
        self.tab_view.pack(fill="both", expand=True, padx=0, pady=0)

        tabs = ["🏢 Company", "🎨 Colors", "📄 Cover Page",
                "📋 Structure", "🖼️ Logo", "📝 Header & Footer"]
        for t in tabs:
            self.tab_view.add(t)

        self._build_company_tab()
        self._build_colors_tab()
        self._build_cover_tab()
        self._build_structure_tab()
        self._build_logo_tab()
        self._build_header_footer_tab()

        # Bottom bar
        bar = ctk.CTkFrame(self, fg_color=PANEL_BG, corner_radius=0, height=60)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)

        ctk.CTkButton(bar, text="💾  Save All Settings", height=38, width=200,
                      corner_radius=BTN_RADIUS, fg_color=ACCENT, hover_color=ACCENT_HOVER,
                      font=FONT_BTN, command=self._save).pack(side="right", padx=16, pady=10)
        ctk.CTkButton(bar, text="Cancel", height=38, width=100,
                      corner_radius=BTN_RADIUS, fg_color="transparent",
                      border_color=BORDER, border_width=1,
                      text_color=TEXT_MUTED, hover_color=CARD_BG,
                      font=FONT_BODY, command=self.destroy).pack(side="right", padx=(0, 8), pady=10)

        self.status_lbl = ctk.CTkLabel(bar, text="", font=FONT_SMALL, text_color=ACCENT)
        self.status_lbl.pack(side="left", padx=16)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _field(self, frame, label, config_path: str, placeholder="", row_pad=(6, 2)):
        keys = config_path.split(".")
        val = self.config
        for k in keys:
            val = val.get(k, "")
        ctk.CTkLabel(frame, text=label, font=FONT_SMALL,
                     text_color=TEXT_MUTED, anchor="w").pack(padx=16, pady=(row_pad[0], row_pad[1]), fill="x")
        e = ctk.CTkEntry(frame, height=ENTRY_HEIGHT, placeholder_text=placeholder,
                         fg_color=CARD_BG, border_color=BORDER, text_color=TEXT_PRIMARY)
        e.pack(padx=16, fill="x")
        if val:
            e.insert(0, str(val))
        return e, config_path

    def _toggle(self, frame, label, config_path: str):
        keys = config_path.split(".")
        val = self.config
        for k in keys:
            val = val.get(k, True)
        var = ctk.BooleanVar(value=bool(val))
        sw = ctk.CTkSwitch(frame, text=label, variable=var,
                           font=FONT_BODY, text_color=TEXT_PRIMARY,
                           button_color=ACCENT, button_hover_color=ACCENT_HOVER,
                           progress_color=ACCENT)
        sw.pack(anchor="w", padx=16, pady=6)
        return var, config_path

    def _color_btn(self, frame, label, config_path: str):
        keys = config_path.split(".")
        val = self.config
        for k in keys:
            val = val.get(k, "#1D9E75")

        row = ctk.CTkFrame(frame, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(row, text=label, font=FONT_SMALL,
                     text_color=TEXT_MUTED, width=200, anchor="w").pack(side="left")
        preview = ctk.CTkLabel(row, text=f"  {val}  ", font=FONT_MONO,
                               text_color=TEXT_PRIMARY, fg_color=val,
                               corner_radius=4, width=100)
        preview.pack(side="left", padx=8)

        hex_var = ctk.StringVar(value=val)

        def pick_color(pv=preview, hv=hex_var, cp=config_path):
            color = colorchooser.askcolor(color=hv.get(), parent=self)
            if color and color[1]:
                hv.set(color[1])
                pv.configure(text=f"  {color[1]}  ", fg_color=color[1])
                self._set_nested(self.config, cp.split("."), color[1])

        ctk.CTkButton(row, text="Pick Color", height=30, width=90,
                      corner_radius=BTN_RADIUS, fg_color=CARD_BG,
                      hover_color=BORDER, text_color=TEXT_PRIMARY,
                      font=FONT_SMALL, command=pick_color).pack(side="left", padx=4)
        return hex_var, config_path

    def _section(self, tab_name: str, title: str) -> ctk.CTkFrame:
        tab = self.tab_view.tab(tab_name)
        if not hasattr(tab, "_scroll"):
            s = ctk.CTkScrollableFrame(tab, fg_color=DARK_BG)
            s.pack(fill="both", expand=True)
            tab._scroll = s
        card = ctk.CTkFrame(tab._scroll, fg_color=PANEL_BG, corner_radius=CARD_RADIUS)
        card.pack(fill="x", padx=20, pady=(12, 0))
        ctk.CTkLabel(card, text=title, font=FONT_SUBHEAD,
                     text_color=ACCENT).pack(anchor="w", padx=16, pady=(12, 4))
        return card

    @staticmethod
    def _set_nested(d: dict, keys: list, val):
        for k in keys[:-1]:
            d = d.setdefault(k, {})
        d[keys[-1]] = val

    # ── Tab: Company ──────────────────────────────────────────────────────────

    def _build_company_tab(self):
        self._entries = []

        s = self._section("🏢 Company", "Company Information")
        fields = [
            ("Company Name *",    "company.name",    "e.g. AcmeSec Pvt. Ltd."),
            ("Tagline",           "company.tagline", "e.g. Cybersecurity & Pentesting Services"),
            ("Website",           "company.website", "www.yourcompany.com"),
            ("Security Email",    "company.email",   "security@yourcompany.com"),
            ("Phone",             "company.phone",   "+91-XXXXXXXXXX"),
            ("Address",           "company.address", "City, Country"),
        ]
        for label, path, ph in fields:
            e, p = self._field(s, label, path, ph)
            self._entries.append((e, p))
        ctk.CTkLabel(s, text="", height=6).pack()

    # ── Tab: Colors ───────────────────────────────────────────────────────────

    def _build_colors_tab(self):
        self._colors = []
        s = self._section("🎨 Colors", "Report Color Scheme")
        ctk.CTkLabel(s, text="Click any color to pick a new one. Changes preview instantly.",
                     font=FONT_SMALL, text_color=TEXT_MUTED).pack(anchor="w", padx=16, pady=(0, 8))

        color_fields = [
            ("Accent / Highlight Color",  "colors.accent"),
            ("Accent Dark (hover)",        "colors.accent_dark"),
            ("Header Background",          "colors.header_bg"),
            ("Header Text",                "colors.header_text"),
            ("Cover Page Background",      "colors.cover_bg"),
            ("Cover Page Text",            "colors.cover_text"),
            ("Body Text",                  "colors.body_text"),
            ("Muted / Label Text",         "colors.muted_text"),
            ("Border Color",               "colors.border"),
            ("Table Alternate Row",        "colors.table_alt_row"),
        ]
        for label, path in color_fields:
            hv, p = self._color_btn(s, label, path)
            self._colors.append((hv, p))
        ctk.CTkLabel(s, text="", height=6).pack()

    # ── Tab: Cover Page ───────────────────────────────────────────────────────

    def _build_cover_tab(self):
        self._cover_toggles = []
        self._cover_entries = []

        s = self._section("📄 Cover Page", "Cover Page Options")
        ctk.CTkLabel(s, text="Control what appears on the report cover page.",
                     font=FONT_SMALL, text_color=TEXT_MUTED).pack(anchor="w", padx=16, pady=(0, 6))

        toggles = [
            ("Show company logo on cover",     "cover_page.show_logo"),
            ("Show company name on cover",     "cover_page.show_company_name"),
            ("Show company tagline on cover",  "cover_page.show_company_tagline"),
            ("Show classification banner",     "cover_page.classification_banner"),
            ("Show report version",            "cover_page.show_report_version"),
        ]
        for label, path in toggles:
            var, p = self._toggle(s, label, path)
            self._cover_toggles.append((var, p))

        ctk.CTkFrame(s, fg_color=BORDER, height=1).pack(fill="x", padx=16, pady=10)

        e, p = self._field(s, "Custom Cover Title (leave blank to use assessment type)",
                           "cover_page.custom_cover_title",
                           "e.g. VAPT Report | Web Application Security Assessment")
        self._cover_entries.append((e, p))
        e2, p2 = self._field(s, "Custom Cover Footer Note (optional)",
                             "cover_page.custom_footer_note",
                             "e.g. Prepared under NDA — Do not distribute")
        self._cover_entries.append((e2, p2))
        ctk.CTkLabel(s, text="", height=6).pack()

    # ── Tab: Structure ────────────────────────────────────────────────────────

    def _build_structure_tab(self):
        self._structure_toggles = []

        s = self._section("📋 Structure", "Report Sections")
        ctk.CTkLabel(s, text="Enable or disable sections in the generated report.",
                     font=FONT_SMALL, text_color=TEXT_MUTED).pack(anchor="w", padx=16, pady=(0, 6))

        toggles = [
            ("Table of Contents (linked index on page 2)", "report_structure.show_toc"),
            ("Executive Summary section",                  "report_structure.show_executive_summary"),
            ("Vulnerability Summary cards",                "report_structure.show_summary_cards"),
            ("Findings Overview table",                    "report_structure.show_findings_table"),
            ("Detailed Findings section",                  "report_structure.show_detailed_findings"),
            ("Disclaimer section",                         "report_structure.show_disclaimer"),
            ("Each vulnerability on its own page",         "report_structure.each_vuln_new_page"),
        ]
        for label, path in toggles:
            var, p = self._toggle(s, label, path)
            self._structure_toggles.append((var, p))
        ctk.CTkLabel(s, text="", height=6).pack()

    # ── Tab: Logo ─────────────────────────────────────────────────────────────

    def _build_logo_tab(self):
        s = self._section("🖼️ Logo", "Company Logo")
        ctk.CTkLabel(s,
                     text="Select your company logo image (PNG or JPG recommended, transparent background preferred).",
                     font=FONT_SMALL, text_color=TEXT_MUTED, wraplength=660).pack(
            anchor="w", padx=16, pady=(0, 10))

        current = self.config.get("branding", {}).get("logo_path", "")
        self.logo_lbl = ctk.CTkLabel(s,
                                      text=f"Current: {current or 'No logo set'}",
                                      font=FONT_MONO, text_color=TEXT_MUTED)
        self.logo_lbl.pack(anchor="w", padx=16, pady=(0, 6))

        ctk.CTkButton(s, text="📁  Browse for Logo Image", height=BTN_HEIGHT,
                      corner_radius=BTN_RADIUS, fg_color=CARD_BG, hover_color=BORDER,
                      text_color=TEXT_PRIMARY, font=FONT_BODY,
                      command=self._pick_logo).pack(padx=16, pady=(0, 6), fill="x")

        ctk.CTkButton(s, text="✕  Clear Logo", height=BTN_HEIGHT - 4,
                      corner_radius=BTN_RADIUS, fg_color="transparent",
                      border_color=BORDER, border_width=1,
                      text_color=TEXT_MUTED, hover_color=CARD_BG,
                      font=FONT_SMALL, command=self._clear_logo).pack(padx=16, fill="x")

        ctk.CTkFrame(s, fg_color=BORDER, height=1).pack(fill="x", padx=16, pady=12)

        size_row = ctk.CTkFrame(s, fg_color="transparent")
        size_row.pack(fill="x", padx=16, pady=(0, 6))
        size_row.columnconfigure((0, 1), weight=1)

        ctk.CTkLabel(size_row, text="Logo Width (mm)", font=FONT_SMALL,
                     text_color=TEXT_MUTED, anchor="w").grid(row=0, column=0, sticky="w", pady=(0, 2))
        self.logo_w = ctk.CTkEntry(size_row, height=ENTRY_HEIGHT,
                                   fg_color=CARD_BG, border_color=BORDER, text_color=TEXT_PRIMARY)
        self.logo_w.grid(row=1, column=0, sticky="ew", padx=(0, 10))
        self.logo_w.insert(0, str(self.config.get("branding", {}).get("logo_width_mm", 40)))

        ctk.CTkLabel(size_row, text="Logo Height (mm)", font=FONT_SMALL,
                     text_color=TEXT_MUTED, anchor="w").grid(row=0, column=1, sticky="w", pady=(0, 2))
        self.logo_h = ctk.CTkEntry(size_row, height=ENTRY_HEIGHT,
                                   fg_color=CARD_BG, border_color=BORDER, text_color=TEXT_PRIMARY)
        self.logo_h.grid(row=1, column=1, sticky="ew")
        self.logo_h.insert(0, str(self.config.get("branding", {}).get("logo_height_mm", 20)))
        ctk.CTkLabel(s, text="", height=6).pack()

    def _pick_logo(self):
        path = filedialog.askopenfilename(
            parent=self,
            title="Select Company Logo",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.gif *.bmp"), ("All files", "*.*")]
        )
        if path:
            self.config.setdefault("branding", {})["logo_path"] = path
            self.logo_lbl.configure(text=f"Current: {path}")

    def _clear_logo(self):
        self.config.setdefault("branding", {})["logo_path"] = ""
        self.logo_lbl.configure(text="Current: No logo set")

    # ── Tab: Header & Footer ──────────────────────────────────────────────────

    def _build_header_footer_tab(self):
        self._hf_toggles = []
        self._hf_entries = []

        s = self._section("📝 Header & Footer", "Page Header & Footer")
        ctk.CTkLabel(s,
                     text="Available placeholders: {client_name}, {assessment_type}, {company_name}, {page}, {total_pages}, {date}",
                     font=FONT_SMALL, text_color=ACCENT, wraplength=660).pack(
            anchor="w", padx=16, pady=(0, 10))

        for label, path in [("Show page header", "header_footer.show_header"),
                             ("Show page footer", "header_footer.show_footer"),
                             ("Show page numbers", "header_footer.show_page_numbers")]:
            var, p = self._toggle(s, label, path)
            self._hf_toggles.append((var, p))

        ctk.CTkFrame(s, fg_color=BORDER, height=1).pack(fill="x", padx=16, pady=10)

        hf_fields = [
            ("Header — Left side",   "header_footer.header_left",   "{client_name}"),
            ("Header — Right side",  "header_footer.header_right",  "{assessment_type}"),
            ("Footer — Left side",   "header_footer.footer_left",   "CONFIDENTIAL — {client_name}"),
            ("Footer — Center",      "header_footer.footer_center", "{company_name}"),
            ("Footer — Right side",  "header_footer.footer_right",  "Page {page} of {total_pages}"),
        ]
        for label, path, ph in hf_fields:
            e, p = self._field(s, label, path, ph)
            self._hf_entries.append((e, p))
        ctk.CTkLabel(s, text="", height=6).pack()

    # ── Save ──────────────────────────────────────────────────────────────────

    def _save(self):
        # Company entries
        for e, path in self._entries:
            self._set_nested(self.config, path.split("."), e.get().strip())

        # Cover entries
        for e, path in self._cover_entries:
            self._set_nested(self.config, path.split("."), e.get().strip())

        # HF entries
        for e, path in self._hf_entries:
            self._set_nested(self.config, path.split("."), e.get().strip())

        # Toggles
        for var, path in (self._cover_toggles + self._structure_toggles + self._hf_toggles):
            self._set_nested(self.config, path.split("."), var.get())

        # Logo dimensions
        try:
            self._set_nested(self.config, ["branding", "logo_width_mm"],
                             float(self.logo_w.get() or 40))
            self._set_nested(self.config, ["branding", "logo_height_mm"],
                             float(self.logo_h.get() or 20))
        except ValueError:
            pass

        ok = save_config(self.config)
        if ok:
            self.status_lbl.configure(text="✅  Settings saved successfully!", text_color=ACCENT)
            self.after(3000, lambda: self.status_lbl.configure(text=""))
        else:
            messagebox.showerror("Error", "Failed to save settings.", parent=self)
