"""
config_manager.py — Load and save report_config.json
"""
import json
import os

CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "report_config.json")


def load_config() -> dict:
    """Load config from JSON. Returns defaults if file missing."""
    if not os.path.exists(CONFIG_PATH):
        return _defaults()
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return _defaults()


def save_config(config: dict) -> bool:
    """Save config dict to JSON. Returns True on success."""
    try:
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        return True
    except Exception:
        return False


def get(key_path: str, default=None):
    """
    Get a nested config value by dot-separated key path.
    e.g. get('company.name') or get('colors.accent')
    """
    config = load_config()
    keys = key_path.split(".")
    val = config
    try:
        for k in keys:
            val = val[k]
        return val
    except (KeyError, TypeError):
        return default


def hex_to_rgb(hex_color: str) -> tuple:
    """Convert #RRGGBB to (R, G, B) tuple of ints."""
    h = hex_color.lstrip("#")
    return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))


def _defaults() -> dict:
    return {
        "company": {
            "name": "Your Company Name",
            "tagline": "Cybersecurity & Penetration Testing Services",
            "website": "",
            "email": "",
        },
        "branding": {"logo_path": "", "logo_width_mm": 40, "logo_height_mm": 20},
        "colors": {
            "accent":        "#1D9E75",
            "accent_dark":   "#0F6E56",
            "header_bg":     "#0D1117",
            "header_text":   "#FFFFFF",
            "cover_bg":      "#0D1117",
            "cover_text":    "#FFFFFF",
            "body_text":     "#1F2328",
            "muted_text":    "#636E7B",
            "border":        "#D0D7DE",
            "table_alt_row": "#F6F8FA",
        },
        "cover_page": {
            "show_logo": True, "show_company_name": True,
            "show_company_tagline": True, "classification_banner": True,
            "show_report_version": True, "custom_cover_title": "",
            "custom_footer_note": "",
        },
        "report_structure": {
            "show_toc": True, "show_executive_summary": True,
            "show_summary_cards": True, "show_findings_table": True,
            "show_detailed_findings": True, "show_disclaimer": True,
            "each_vuln_new_page": True,
        },
        "header_footer": {
            "show_header": True,
            "header_left": "{client_name}", "header_right": "{assessment_type}",
            "show_footer": True,
            "footer_left": "CONFIDENTIAL — {client_name}",
            "footer_right": "Page {page} of {total_pages}",
            "footer_center": "{company_name}",
            "show_page_numbers": True,
        },
        "disclaimer": {
            "text": (
                "This report is prepared for the exclusive and confidential use of the client "
                "named above. The findings presented are based on a time-limited assessment and "
                "may not represent all vulnerabilities present."
            ),
            "poc_note": (
                "NOTE: Screenshots and POC evidence must be added manually in the Word report."
            ),
        },
    }
