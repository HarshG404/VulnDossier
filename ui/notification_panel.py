"""
notification_panel.py — VulnDossier Notification Bell + Dropdown.

Renders as a Frame placed() over the main window — NOT a Toplevel.
This avoids ALL window-manager bugs (deiconify, bad window path, etc.).
After() loop is properly cancelled on destroy.
"""
import customtkinter as ctk
from ui.theme import *
from database.db_manager import (
    get_notifications, count_unread_notifications,
    mark_notification_read, mark_all_notifications_read
)
from utils.helpers import format_dt

NOTIF_COLORS = {
    "info":       (SEV_COLORS["Informational"]["fg"], SEV_COLORS["Informational"]["bg"]),
    "success":    (SEV_COLORS["Low"]["fg"],            SEV_COLORS["Low"]["bg"]),
    "warning":    (SEV_COLORS["Medium"]["fg"],          SEV_COLORS["Medium"]["bg"]),
    "error":      (SEV_COLORS["Critical"]["fg"],        SEV_COLORS["Critical"]["bg"]),
    "request":    (ACCENT,                              CARD_BG),
    "approval":   (SEV_COLORS["Low"]["fg"],             SEV_COLORS["Low"]["bg"]),
    "rejection":  (SEV_COLORS["Critical"]["fg"],        SEV_COLORS["Critical"]["bg"]),
    "admin_note": (SEV_COLORS["Medium"]["fg"],          SEV_COLORS["Medium"]["bg"]),
    "report":     (SEV_COLORS["Informational"]["fg"],   SEV_COLORS["Informational"]["bg"]),
    "access":     (ACCENT,                              CARD_BG),
}

NOTIF_ICONS = {
    "info": "ℹ️", "success": "✅", "warning": "⚠️",
    "error": "❌", "request": "📨", "approval": "✅",
    "rejection": "❌", "admin_note": "💬", "report": "📄",
    "access": "🏢",
}


class NotificationBell(ctk.CTkFrame):
    """
    Bell icon button that shows unread badge.
    Clicking toggles a dropdown Frame placed on the root window.
    No Toplevel → no window path errors.
    """

    def __init__(self, parent, user_email: str, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)
        self.user_email  = user_email
        self._dropdown   = None   # the overlay Frame (or None)
        self._after_id   = None   # pending after() id
        self._destroyed  = False

        # Bell button
        self._btn = ctk.CTkButton(
            self, text="🔔", width=38, height=34,
            corner_radius=BTN_RADIUS,
            fg_color="transparent",
            hover_color=CARD_BG,
            font=("Segoe UI", 16),
            text_color=TEXT_PRIMARY,
            command=self._toggle
        )
        self._btn.pack(side="left")

        # Unread badge
        self._badge = ctk.CTkLabel(
            self, text="", width=18, height=18,
            corner_radius=9,
            fg_color=SEV_COLORS["Critical"]["fg"],
            text_color=WHITE,
            font=("Segoe UI", 9, "bold")
        )

        self.bind("<Destroy>", self._on_widget_destroy)
        self._schedule_refresh()

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def _on_widget_destroy(self, event=None):
        self._destroyed = True
        if self._after_id:
            try:
                self.after_cancel(self._after_id)
            except Exception:
                pass
            self._after_id = None
        self._close_dropdown()

    def _schedule_refresh(self):
        if self._destroyed:
            return
        try:
            self._refresh_count()
            self._after_id = self.after(30000, self._schedule_refresh)
        except Exception:
            pass

    def _refresh_count(self):
        if self._destroyed:
            return
        try:
            count = count_unread_notifications(self.user_email)
            if count > 0:
                txt = str(count) if count < 100 else "99+"
                self._badge.configure(text=txt)
                self._badge.place(relx=0.6, rely=0.0, anchor="nw")
            else:
                self._badge.place_forget()
        except Exception:
            pass

    def refresh(self):
        self._refresh_count()

    # ── Dropdown toggle ───────────────────────────────────────────────────────

    def _toggle(self):
        if self._dropdown is not None:
            self._close_dropdown()
        else:
            self._open_dropdown()

    def _open_dropdown(self):
        # Find root window
        root = self.winfo_toplevel()

        # Compute position: below the bell button
        self.update_idletasks()
        bx   = self.winfo_rootx() - root.winfo_rootx()
        by   = self.winfo_rooty() - root.winfo_rooty() + self.winfo_height() + 4
        pw   = 360
        ph   = 460
        # Clamp so it doesn't go off right edge
        rx   = root.winfo_width()
        px   = min(bx, rx - pw - 10)
        px   = max(10, px)

        # Build the overlay frame — width/height MUST go in constructor for CTkFrame
        self._dropdown = _NotifDropdown(
            root,
            user_email=self.user_email,
            on_close=self._close_dropdown,
            on_read=self._refresh_count,
            width=pw,
            height=ph,
        )
        self._dropdown.place(x=px, y=by)
        self._dropdown.lift()

        # Close if user clicks anywhere outside
        root.bind("<Button-1>", self._check_outside_click, add="+")

    def _close_dropdown(self):
        if self._dropdown is not None:
            try:
                # Unbind root click handler
                root = self.winfo_toplevel()
                root.unbind("<Button-1>")
            except Exception:
                pass
            try:
                self._dropdown.place_forget()
                self._dropdown.destroy()
            except Exception:
                pass
            self._dropdown = None
        self._refresh_count()

    def _check_outside_click(self, event):
        """Close dropdown if click is outside it."""
        if self._dropdown is None:
            return
        try:
            dx = self._dropdown.winfo_rootx()
            dy = self._dropdown.winfo_rooty()
            dw = self._dropdown.winfo_width()
            dh = self._dropdown.winfo_height()
            if not (dx <= event.x_root <= dx + dw and
                    dy <= event.y_root <= dy + dh):
                self._close_dropdown()
        except Exception:
            self._close_dropdown()


class _NotifDropdown(ctk.CTkFrame):
    """
    The actual dropdown panel — a Frame placed on the root window.
    Not a window, so no titlebar, no deiconify, no window path issues.
    width/height passed to constructor as required by CustomTkinter.
    """

    def __init__(self, parent, user_email: str, on_close=None, on_read=None,
                 width=360, height=460):
        super().__init__(
            parent,
            fg_color=PANEL_BG,
            corner_radius=CARD_RADIUS,
            border_width=1,
            border_color=BORDER,
            width=width,
            height=height,
        )
        self.user_email = user_email
        self.on_close   = on_close
        self.on_read    = on_read
        self._build()

    def _build(self):
        # Header
        hdr = ctk.CTkFrame(self, fg_color=DARK_BG, corner_radius=0, height=42)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="🔔  Notifications",
                     font=FONT_SUBHEAD, text_color=TEXT_PRIMARY).pack(
            side="left", padx=12, pady=10)
        ctk.CTkButton(hdr, text="✓ All read",
                      height=26, width=80,
                      corner_radius=BTN_RADIUS,
                      fg_color="transparent",
                      hover_color=CARD_BG,
                      text_color=TEXT_MUTED,
                      font=FONT_SMALL,
                      command=self._mark_all).pack(side="right", padx=8)
        ctk.CTkButton(hdr, text="✕",
                      height=26, width=30,
                      corner_radius=BTN_RADIUS,
                      fg_color="transparent",
                      hover_color=CARD_BG,
                      text_color=TEXT_MUTED,
                      font=FONT_SMALL,
                      command=self._close).pack(side="right", padx=(0, 4))

        # Scrollable list
        self._scroll = ctk.CTkScrollableFrame(self, fg_color=PANEL_BG)
        self._scroll.pack(fill="both", expand=True)
        self._load()

    def _load(self):
        for w in self._scroll.winfo_children():
            w.destroy()

        notifs = get_notifications(self.user_email)
        if not notifs:
            ctk.CTkLabel(self._scroll,
                         text="No notifications yet.",
                         font=FONT_SMALL,
                         text_color=TEXT_MUTED).pack(padx=14, pady=28)
            return

        for n in notifs:
            ntype   = n.get("notif_type", "info")
            fg, bg  = NOTIF_COLORS.get(ntype, NOTIF_COLORS["info"])
            icon    = NOTIF_ICONS.get(ntype, "ℹ️")
            is_read = bool(n.get("is_read", 0))

            card = ctk.CTkFrame(
                self._scroll,
                fg_color=DARK_BG if is_read else bg,
                corner_radius=8
            )
            card.pack(fill="x", padx=8, pady=3)

            if not is_read:
                ctk.CTkFrame(card, fg_color=fg, width=3,
                             corner_radius=0).pack(side="left", fill="y")

            body = ctk.CTkFrame(card, fg_color="transparent")
            body.pack(side="left", fill="x", expand=True, padx=8, pady=6)

            # Title + mark-read button
            tr = ctk.CTkFrame(body, fg_color="transparent")
            tr.pack(fill="x")
            ctk.CTkLabel(
                tr,
                text=f"{icon} {n['title']}",
                font=("Segoe UI", 10, "bold") if not is_read else FONT_SMALL,
                text_color=fg if not is_read else TEXT_MUTED,
                anchor="w"
            ).pack(side="left", fill="x", expand=True)

            if not is_read:
                ctk.CTkButton(
                    tr, text="✓", width=22, height=18,
                    corner_radius=4,
                    fg_color="transparent",
                    hover_color=CARD_BG,
                    text_color=TEXT_MUTED,
                    font=FONT_SMALL,
                    command=lambda nid=n["id"]: self._mark_one(nid)
                ).pack(side="right")

            ctk.CTkLabel(
                body, text=n["message"],
                font=FONT_SMALL,
                text_color=TEXT_PRIMARY if not is_read else TEXT_MUTED,
                anchor="w", wraplength=280, justify="left"
            ).pack(fill="x", pady=(2, 0))

            ctk.CTkLabel(
                body, text=format_dt(n["created_at"]),
                font=("Segoe UI", 9),
                text_color=TEXT_MUTED, anchor="w"
            ).pack(fill="x")

    def _mark_one(self, notif_id: int):
        mark_notification_read(notif_id)
        self._load()
        if self.on_read:
            self.on_read()

    def _mark_all(self):
        mark_all_notifications_read(self.user_email)
        self._load()
        if self.on_read:
            self.on_read()

    def _close(self):
        if self.on_close:
            self.on_close()
