"""
email_sender.py — SMTP email sending for VulnDossier v2.0
Sends auth codes from pentester email to manager email via TLS.
Config stored in config/email_config.json
"""
import smtplib
import json
import os
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

EMAIL_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "config", "email_config.json"
)

DEFAULT_CONFIG = {
    "_instructions": (
        "Fill in your SMTP details to enable email notifications. "
        "For Gmail: use smtp.gmail.com port 587 and an App Password "
        "(not your regular password — generate one at myaccount.google.com/apppasswords). "
        "For Outlook: use smtp-mail.outlook.com port 587."
    ),
    "enabled": False,
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 587,
    "use_tls": True,
    "sender_email": "",
    "sender_password": "",
    "sender_name": "VulnDossier",
    "reply_to": ""
}


def load_email_config() -> dict:
    if not os.path.exists(EMAIL_CONFIG_PATH):
        _save_default()
    try:
        with open(EMAIL_CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return DEFAULT_CONFIG.copy()


def save_email_config(config: dict) -> bool:
    try:
        os.makedirs(os.path.dirname(EMAIL_CONFIG_PATH), exist_ok=True)
        with open(EMAIL_CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        return True
    except Exception:
        return False


def _save_default():
    save_email_config(DEFAULT_CONFIG.copy())


def is_email_configured() -> bool:
    cfg = load_email_config()
    return (
        cfg.get("enabled", False) and
        bool(cfg.get("sender_email")) and
        bool(cfg.get("sender_password"))
    )


def _build_auth_email(
    project_name: str,
    client_name: str,
    pentester_name: str,
    pentester_email: str,
    manager_email: str,
    auth_code: str,
    start_date: str,
    end_date: str,
    project_type: str,
    scope: str,
) -> MIMEMultipart:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[VulnDossier] Approval Required — {project_name}"
    msg["From"]    = pentester_email
    msg["To"]      = manager_email
    msg["Reply-To"] = pentester_email

    plain = f"""
Dear Manager,

A new penetration test request has been submitted and requires your approval.

PROJECT DETAILS
---------------
Project Name   : {project_name}
Client / Target: {client_name}
Assessment Type: {project_type}
Scope          : {scope}
Start Date     : {start_date}
End Date       : {end_date}
Requested By   : {pentester_name} ({pentester_email})

AUTHENTICATION CODE
-------------------
Your approval code is: {auth_code}

To approve this request, share this code with {pentester_name}.
They will enter it in the VulnDossier tool to begin the assessment.

If you did not expect this request or wish to reject it, simply ignore this email
and do NOT share the code.

This email was sent automatically by VulnDossier v2.0.
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
""".strip()

    html_body = f"""
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:Segoe UI,Arial,sans-serif;background:#f5f5f5;margin:0;padding:20px">
<div style="max-width:600px;margin:0 auto;background:#fff;border-radius:8px;overflow:hidden;border:1px solid #e0e0e0">
  <div style="background:#0D1117;padding:24px 28px">
    <h2 style="color:#1D9E75;margin:0;font-size:20px">VulnDossier</h2>
    <p style="color:#8B949E;margin:6px 0 0;font-size:13px">Approval Required</p>
  </div>
  <div style="padding:28px">
    <p style="color:#333;font-size:15px;margin:0 0 20px">Dear Manager,</p>
    <p style="color:#555;font-size:14px;line-height:1.6">
      A new penetration test has been requested and requires your approval before it can begin.
    </p>

    <div style="background:#f9f9f9;border-radius:6px;padding:18px;margin:20px 0;border:1px solid #e8e8e8">
      <h3 style="margin:0 0 12px;color:#0D1117;font-size:14px;text-transform:uppercase;letter-spacing:.05em">Project Details</h3>
      <table style="width:100%;font-size:13px;border-collapse:collapse">
        <tr><td style="color:#888;padding:5px 0;width:140px">Project Name</td><td style="color:#333;font-weight:500">{project_name}</td></tr>
        <tr><td style="color:#888;padding:5px 0">Client / Target</td><td style="color:#333">{client_name}</td></tr>
        <tr><td style="color:#888;padding:5px 0">Assessment Type</td><td style="color:#333">{project_type}</td></tr>
        <tr><td style="color:#888;padding:5px 0">Scope</td><td style="color:#333;word-break:break-all">{scope}</td></tr>
        <tr><td style="color:#888;padding:5px 0">Period</td><td style="color:#333">{start_date} → {end_date}</td></tr>
        <tr><td style="color:#888;padding:5px 0">Requested By</td><td style="color:#333">{pentester_name}</td></tr>
      </table>
    </div>

    <div style="background:#0D1117;border-radius:8px;padding:20px;text-align:center;margin:24px 0">
      <p style="color:#8B949E;font-size:12px;margin:0 0 8px;text-transform:uppercase;letter-spacing:.08em">Your Approval Code</p>
      <div style="font-size:32px;font-weight:bold;letter-spacing:8px;color:#1D9E75;font-family:Consolas,monospace">{auth_code}</div>
      <p style="color:#8B949E;font-size:11px;margin:10px 0 0">Share this code with {pentester_name} to approve the assessment</p>
    </div>

    <div style="background:#FFF3CD;border-left:4px solid #F0883E;padding:12px 16px;border-radius:0 6px 6px 0;margin:16px 0">
      <p style="color:#7A4910;font-size:13px;margin:0">
        <strong>Security Notice:</strong> If you did not expect this request, do NOT share this code.
        Simply ignore this email to reject the request.
      </p>
    </div>

    <p style="color:#999;font-size:12px;margin:24px 0 0">
      Sent automatically by VulnDossier v2.0 on {datetime.now().strftime('%B %d, %Y at %H:%M')}
    </p>
  </div>
</div>
</body>
</html>
""".strip()

    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html_body, "html"))
    return msg


def send_auth_code_email(
    project_name: str,
    client_name: str,
    pentester_name: str,
    pentester_email: str,
    manager_email: str,
    auth_code: str,
    start_date: str,
    end_date: str,
    project_type: str,
    scope: str,
    smtp_sender_email: str = "",
    smtp_app_password: str = "",
) -> tuple:
    """
    Send the auth code email to the manager.
    Uses user-specific SMTP if provided, falls back to global admin config.
    Returns (success: bool, message: str)
    """
    # Prefer user-level SMTP over global admin config
    if smtp_sender_email and smtp_app_password:
        sender_email = smtp_sender_email
        sender_pw    = smtp_app_password
        smtp_host    = "smtp.gmail.com"
        smtp_port    = 587
        use_tls      = True
        sender_name  = "VulnDossier"
    else:
        cfg = load_email_config()
        if not cfg.get("enabled", False):
            return False, "Email not configured. Share auth code manually."
        if not cfg.get("sender_email") or not cfg.get("sender_password"):
            return False, "Global SMTP credentials missing. Configure in Admin Panel."
        sender_email = cfg["sender_email"]
        sender_pw    = cfg["sender_password"]
        smtp_host    = cfg.get("smtp_host", "smtp.gmail.com")
        smtp_port    = cfg.get("smtp_port", 587)
        use_tls      = cfg.get("use_tls", True)
        sender_name  = cfg.get("sender_name", "VulnDossier")

    try:
        msg = _build_auth_email(
            project_name, client_name, pentester_name, pentester_email,
            manager_email, auth_code, start_date, end_date, project_type, scope
        )
        msg["From"] = f"{sender_name} <{sender_email}>"

        context = ssl.create_default_context()
        if use_tls:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                server.login(sender_email, sender_pw)
                server.sendmail(sender_email, [manager_email], msg.as_string())
        else:
            with smtplib.SMTP_SSL(smtp_host, smtp_port,
                                   context=context, timeout=15) as server:
                server.login(sender_email, sender_pw)
                server.sendmail(sender_email, [manager_email], msg.as_string())

        return True, f"Auth code emailed to {manager_email} successfully."

    except smtplib.SMTPAuthenticationError:
        return False, (
            "SMTP authentication failed. For Gmail, use an App Password\n"
            "(not your regular password). Update in Profile → Email Settings."
        )
    except smtplib.SMTPException as e:
        return False, f"Email sending failed: {str(e)}"
    except Exception as e:
        return False, f"Unexpected error: {str(e)}"


def test_smtp_connection(cfg: dict) -> tuple:
    """Test SMTP connection with given config. Returns (success, message)."""
    try:
        context = ssl.create_default_context()
        if cfg.get("use_tls", True):
            with smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"], timeout=10) as server:
                server.ehlo()
                server.starttls(context=context)
                server.login(cfg["sender_email"], cfg["sender_password"])
        else:
            with smtplib.SMTP_SSL(cfg["smtp_host"], cfg["smtp_port"],
                                   context=context, timeout=10) as server:
                server.login(cfg["sender_email"], cfg["sender_password"])
        return True, "Connection successful! SMTP is working correctly."
    except smtplib.SMTPAuthenticationError:
        return False, "Authentication failed. Check email/password."
    except Exception as e:
        return False, f"Connection failed: {str(e)}"
