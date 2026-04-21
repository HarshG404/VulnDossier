"""
theme.py — Centralized colors, fonts, and widget styles for the entire app
"""

# ── Palette ───────────────────────────────────────────────────────────────────
DARK_BG       = "#0D1117"
PANEL_BG      = "#161B22"
CARD_BG       = "#21262D"
BORDER        = "#30363D"
ACCENT        = "#1D9E75"
ACCENT_HOVER  = "#17856A"
ACCENT_LIGHT  = "#E6FBF3"
TEXT_PRIMARY  = "#E6EDF3"
TEXT_MUTED    = "#8B949E"
TEXT_LINK     = "#58A6FF"
WHITE         = "#FFFFFF"
BLACK         = "#000000"

SEV_COLORS = {
    "Critical":      {"fg": "#FF7B72", "bg": "#2D1111"},
    "High":          {"fg": "#F0883E", "bg": "#2D1A0A"},
    "Medium":        {"fg": "#D29922", "bg": "#2D2107"},
    "Low":           {"fg": "#3FB950", "bg": "#0D2A14"},
    "Informational": {"fg": "#58A6FF", "bg": "#0D1F2D"},
}

STATUS_COLORS = {
    "Request Pending":  "#F0883E",
    "Waiting to start": "#D29922",
    "Running":          "#3FB950",
    "Admin Review":     "#58A6FF",
    "Completed":        "#1D9E75",
    "Hold":             "#FF7B72",
    "Rejected":         "#FF7B72",
}

# ── Fonts ─────────────────────────────────────────────────────────────────────
FONT_TITLE    = ("Segoe UI", 22, "bold")
FONT_HEADING  = ("Segoe UI", 15, "bold")
FONT_SUBHEAD  = ("Segoe UI", 13, "bold")
FONT_BODY     = ("Segoe UI", 12)
FONT_SMALL    = ("Segoe UI", 10)
FONT_MONO     = ("Consolas", 11)
FONT_BTN      = ("Segoe UI", 12, "bold")

# ── CTk appearance ────────────────────────────────────────────────────────────
CTK_THEME = "dark"
CTK_COLOR = "dark-blue"

# Widget defaults
ENTRY_HEIGHT   = 36
BTN_HEIGHT     = 38
BTN_RADIUS     = 8
CARD_RADIUS    = 10
PADDING        = 16
