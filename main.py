#!/usr/bin/env python3
"""
main.py — VulnDossier v2.0
Entry point: shows login window, then dashboard after successful login.

Usage:
    python main.py
"""
import sys
import os

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(__file__))

from database.db_manager import initialize_db


def main():
    # Initialize DB on first run
    initialize_db()

    try:
        import customtkinter as ctk
    except ImportError:
        print("\n[✗] customtkinter is not installed.")
        print("    Run: pip install customtkinter\n")
        sys.exit(1)

    from ui.login_window import LoginWindow
    from ui.dashboard_window import DashboardWindow

    def on_login_success(user, login_win):
        dash = DashboardWindow(user, login_win)
        dash.mainloop()

    app = LoginWindow(on_login_success=on_login_success)
    app.mainloop()


if __name__ == "__main__":
    main()
