"""
otp_manager.py — OTP generation, email delivery, and verification helpers.
OTPs are 6-character alphanumeric codes sent from the admin's email.
"""
import secrets
import string
from datetime import datetime, timedelta

from utils.email_sender import load_email_config
from database.db_manager import (
    set_user_otp, verify_user_otp, confirm_email_verified,
    get_admin_smtp_config
)


OTP_EXPIRY_MINUTES = 10
OTP_LENGTH         = 6
OTP_ALPHABET       = string.ascii_uppercase + string.digits
# Remove ambiguous chars
OTP_ALPHABET       = OTP_ALPHABET.replace("O","").replace("0","").replace("I","").replace("1","")


def generate_otp() -> str:
    """Generate a secure 6-char alphanumeric OTP."""
    return ''.join(secrets.choice(OTP_ALPHABET) for _ in range(OTP_LENGTH))


def send_otp_email(to_email: str, otp_code: str,
                   purpose: str = "account verification",
                   username: str = "") -> tuple:
    """
    Send OTP email from admin's SMTP config.
    Returns (success: bool, message: str)
    """
    import smtplib, ssl
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    cfg = load_email_config()
    if not cfg.get("enabled", False) or not cfg.get("sender_email") or not cfg.get("sender_password"):
        return False, "Admin SMTP not configured. Please configure Email Settings in Admin Panel first."

    subject = f"[VulnDossier] Your verification code — {otp_code}"

    plain = f"""
VulnDossier — Verification Code
================================

Hello{' ' + username if username else ''},

Your one-time verification code for {purpose} is:

    {otp_code}

This code is valid for {OTP_EXPIRY_MINUTES} minutes.
Do not share this code with anyone.

If you did not request this code, please ignore this email.

— VulnDossier Security
""".strip()

    html = f"""
<!DOCTYPE html>
<html>
<body style="font-family:Segoe UI,Arial,sans-serif;background:#f5f5f5;padding:20px;margin:0">
<div style="max-width:480px;margin:0 auto;background:#fff;border-radius:8px;overflow:hidden;border:1px solid #e0e0e0">
  <div style="background:#0D1117;padding:20px 24px">
    <h2 style="color:#1D9E75;margin:0;font-size:18px">VulnDossier</h2>
    <p style="color:#8B949E;margin:4px 0 0;font-size:12px">Penetration Test Management Platform</p>
  </div>
  <div style="padding:28px 24px">
    <p style="color:#333;font-size:14px;margin:0 0 8px">Hello{' <b>' + username + '</b>' if username else ''},</p>
    <p style="color:#555;font-size:13px">Your verification code for <b>{purpose}</b>:</p>
    <div style="background:#0D1117;border-radius:8px;padding:20px;text-align:center;margin:20px 0">
      <div style="font-size:36px;font-weight:bold;letter-spacing:10px;color:#1D9E75;font-family:Consolas,monospace">{otp_code}</div>
      <p style="color:#8B949E;font-size:11px;margin:8px 0 0">Valid for {OTP_EXPIRY_MINUTES} minutes</p>
    </div>
    <p style="color:#999;font-size:12px">Do not share this code. If you didn't request it, ignore this email.</p>
  </div>
</div>
</body>
</html>
""".strip()

    msg               = MIMEMultipart("alternative")
    msg["Subject"]    = subject
    msg["From"]       = f"VulnDossier <{cfg['sender_email']}>"
    msg["To"]         = to_email
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html, "html"))

    try:
        ctx = ssl.create_default_context()
        with smtplib.SMTP(cfg.get("smtp_host","smtp.gmail.com"),
                          cfg.get("smtp_port", 587), timeout=15) as server:
            server.ehlo()
            server.starttls(context=ctx)
            server.ehlo()
            server.login(cfg["sender_email"], cfg["sender_password"])
            server.sendmail(cfg["sender_email"], [to_email], msg.as_string())
        return True, f"Verification code sent to {to_email}"
    except Exception as e:
        return False, f"Email failed: {str(e)}"


def send_report_email(to_email: str, pentester_name: str,
                      project_name: str, client_name: str,
                      pdf_path: str, docx_path: str) -> tuple:
    """
    Email the generated reports to the pentester from admin's email.
    """
    import smtplib, ssl, os
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.mime.base import MIMEBase
    from email import encoders

    cfg = load_email_config()
    if not cfg.get("enabled", False) or not cfg.get("sender_email") or not cfg.get("sender_password"):
        return False, "Admin SMTP not configured."

    subject = f"[VulnDossier] Pentest Report — {project_name}"

    body = f"""
Hello {pentester_name},

Your penetration test report for '{project_name}' ({client_name}) has been reviewed and approved by the admin.

Please find the reports attached:
• PDF Report
• Word (.docx) Report

The reports are also saved locally in the output folder.

— VulnDossier
    """.strip()

    msg               = MIMEMultipart()
    msg["Subject"]    = subject
    msg["From"]       = f"VulnDossier Admin <{cfg['sender_email']}>"
    msg["To"]         = to_email
    msg.attach(MIMEText(body, "plain"))

    for fpath in [pdf_path, docx_path]:
        if fpath and os.path.exists(fpath):
            try:
                with open(fpath, "rb") as fp:
                    part = MIMEBase("application", "octet-stream")
                    part.set_payload(fp.read())
                    encoders.encode_base64(part)
                    part.add_header("Content-Disposition",
                                    f"attachment; filename={os.path.basename(fpath)}")
                    msg.attach(part)
            except Exception:
                pass

    try:
        ctx = ssl.create_default_context()
        with smtplib.SMTP(cfg.get("smtp_host","smtp.gmail.com"),
                          cfg.get("smtp_port",587), timeout=30) as server:
            server.ehlo()
            server.starttls(context=ctx)
            server.ehlo()
            server.login(cfg["sender_email"], cfg["sender_password"])
            server.sendmail(cfg["sender_email"], [to_email], msg.as_string())
        return True, f"Report emailed to {to_email}"
    except Exception as e:
        return False, f"Email failed: {str(e)}"


def create_and_send_otp(user_id: int, email: str, otp_type: str,
                        username: str = "", pending_email: str = None) -> tuple:
    """
    Generate OTP, save to DB, send email.
    Returns (success: bool, message: str, otp_code: str)
    otp_type: 'registration' | 'email_change'
    """
    otp_code   = generate_otp()
    expires_at = (datetime.now() + timedelta(minutes=OTP_EXPIRY_MINUTES)).isoformat()
    set_user_otp(user_id, otp_code, otp_type, expires_at, pending_email)

    purpose_map = {
        "registration":  "account registration",
        "email_change":  "email address change",
    }
    purpose = purpose_map.get(otp_type, "verification")
    ok, msg = send_otp_email(email, otp_code, purpose, username)
    return ok, msg, otp_code
