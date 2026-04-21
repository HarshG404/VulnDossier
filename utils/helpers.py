"""
helpers.py — Shared utility functions
"""
import re
import os
from datetime import datetime


def format_dt(iso_str: str, fmt="%d %b %Y, %H:%M") -> str:
    """Format ISO datetime string to human-readable."""
    if not iso_str:
        return "N/A"
    try:
        dt = datetime.fromisoformat(iso_str)
        return dt.strftime(fmt)
    except Exception:
        return iso_str


def format_date(iso_str: str) -> str:
    return format_dt(iso_str, "%d %b %Y")


def severity_icon(sev: str) -> str:
    return {"Critical": "🔴", "High": "🟠", "Medium": "🟡",
            "Low": "🟢", "Informational": "🔵"}.get(sev, "⚪")


def status_icon(status: str) -> str:
    return {
        "Request Pending":  "📨",
        "Waiting to start": "⏳",
        "Running":          "▶️",
        "Admin Review":   "👁️",
        "Completed":        "✅",
        "Hold":             "⏸️",
    }.get(status, "❓")


def validate_date(date_str: str) -> bool:
    try:
        datetime.strptime(date_str.strip(), "%Y-%m-%d")
        return True
    except ValueError:
        return False


def validate_email(email: str) -> bool:
    return bool(re.match(r"^[^@]+@[^@]+\.[^@]+$", email.strip()))


def open_folder(path: str):
    """Open a folder in the OS file explorer."""
    import subprocess, sys
    try:
        if sys.platform == "win32":
            os.startfile(path)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    except Exception:
        pass


def truncate(text: str, max_len: int = 60) -> str:
    text = str(text or "")
    return text if len(text) <= max_len else text[:max_len - 3] + "..."
