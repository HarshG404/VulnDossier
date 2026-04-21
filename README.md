# VulnDossier 🗂️

> **Enterprise Penetration Test Management Platform**  
> Manage the full lifecycle of penetration tests — from request to reviewed report — with POC images, CVSS calculator, email notifications, and org-wide access control.  
> Built by **Harsh Goyal** — Penetration Tester | CEH | CCNA

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![GUI](https://img.shields.io/badge/GUI-CustomTkinter-purple?style=flat-square)](https://github.com/TomSchimansky/CustomTkinter)
[![DB](https://img.shields.io/badge/Database-SQLite-orange?style=flat-square)](https://sqlite.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

---

## 📦 Installation

### Step 1 — Install Python
Download Python 3.10 or higher from [python.org](https://python.org/downloads/).  
**Windows:** During install, tick ✅ **"Add Python to PATH"**

### Step 2 — Extract the zip
Extract `VulnDossier.zip` to any folder, e.g.:
```
C:\Users\YourName\Desktop\VulnDossier\
```

### Step 3 — Open terminal in the folder
**Windows:** Click the address bar in File Explorer → type `cmd` → press Enter

### Step 4 — Install dependencies
```bash
pip install customtkinter reportlab python-docx Pillow
```

### Step 5 — Run the application
```bash
python main.py
```

The login screen will appear. Continue to **First Time Setup** below.

---

## ⚙️ First Time Setup (IMPORTANT — Read Before Using)

After launching the app for the first time, follow these steps in order:

### 1. Login as Administrator
```
Username : administrator
Password : Pa$$w0rd
```

### 2. Go to Admin Panel
Click **🛡️ Admin Panel** in the left sidebar.

### 3. Configure Email Settings
Click **📧 Email Settings** in the admin panel sidebar.

> **Why?** Email is used for OTP verification, password reset, auth codes, and sending final reports to pentesters.

#### Gmail Setup (Recommended)
| Field | Value |
|-------|-------|
| SMTP Host | `smtp.gmail.com` |
| SMTP Port | `587` |
| Use TLS | ✅ ON |
| Sender Email | Your Gmail address |
| App Password | Generate one (see below) |

#### How to get a Gmail App Password
1. Open your Google Account → [myaccount.google.com](https://myaccount.google.com)
2. Go to **Security** → Enable **2-Step Verification** (required)
3. Search for **"App Passwords"** in the search bar
4. Click **App Passwords** → Name it anything (e.g. `VulnDossier`)
5. Copy the 16-character password shown (e.g. `abcd efgh ijkl mnop`)
6. Paste it into the **App Password** field in VulnDossier Email Settings

#### Outlook / Other SMTP
| Field | Value |
|-------|-------|
| SMTP Host | `smtp-mail.outlook.com` |
| SMTP Port | `587` |

Click **🔌 Test Connection** → if it shows ✅, click **💾 Save Settings**.

### 4. Update Admin Email Address
Click **👤 My Profile** in the left sidebar.
- Change the **Email Address** from `admin@vulndossier.local` to your real email
- Enter OTP sent to your email to confirm the change
- Also change your **Password** from the default `Pa$$w0rd` to something strong

### 5. Done!
You can now use all features:
- Create and approve pentest requests
- Send OTP emails for new user registration
- Email final reports to pentesters automatically
- Receive notifications for all activities

---

## 🔐 Default Credentials

| Account | Username | Password |
|---------|----------|----------|
| Admin | `administrator` | `Pa$$w0rd` |
| Email | `admin@vulndossier.local` | *(change via Profile)* |

---

## ✨ Features

### User Management
- **Register** with email OTP verification (6-char alphanumeric code, 10 min expiry)
- **Forgot Password** — enter username/email → receive reset code → set new password
- **Password Policy** — min 8 chars, uppercase, lowercase, digit, special character
- **Live password strength meter** during registration and password change
- **Brute-force protection** — 5 failed attempts = 15-minute lockout
- **Profile page** — change username, email (with OTP), password anytime

### Pentest Request Flow
```
User raises request → Admin approves → User starts pentest
→ Adds vulnerabilities + POC images → Finishes + writes summary
→ Submitted to Admin Review → Admin approves + emails report
→ Project marked Completed
```

### Vulnerability Management
- **CVSS v3.1 Calculator** — built-in metric selector (no manual entry)
- **POC Screenshots** — attach multiple images per vulnerability
- **Steps to Reproduce** — multiline textbox (press Enter for new lines)
- **Open/Closed status** — track which vulns are fixed
- **Auto-renumbering** — VUL-001, VUL-002... renumbered by severity after every change
- **Removed vulnerabilities log** — audit trail in TXT file

### Reports (PDF + Word)
- **Both formats generated simultaneously**
- **Clickable Table of Contents** — links jump to each section and vulnerability
- **Each vulnerability on its own page**
- **All 8 CVSS metrics** displayed (including Integrity and Availability)
- **POC images embedded** under "Steps to Reproduce" for each vulnerability
- **Company branding** — logo, colors, name (configured by admin)
- **Admin emails final report** to pentester automatically on approval

### Admin Panel
| Tab | What it does |
|-----|-------------|
| 📨 Raised Requests | Approve / reject pending pentest requests |
| 📝 Admin Review | Review finished projects, approve & email reports, or request changes |
| 🏢 Org Access | Review user requests for org-wide project access, grant Read or Read+Write |
| 👥 Users | Promote/demote admin, suspend/reactivate accounts |
| 📋 All Projects | View every project across all users |
| 📧 Email Settings | Configure SMTP for all email delivery |
| 📄 Report Settings | Company logo, colors, cover page, report structure |
| 🔍 Audit Log | Last 50 login attempts |

### Notifications 🔔
- Bell icon in top navigation bar for everyone (admin + users)
- Unread count badge updates automatically
- Notifications for: project approvals, report delivery, org access decisions, admin review notes
- Click notification to mark as read, or "Mark all read"

### Org-Wide Project Access
- Users can request access to view all org projects
- Admin controls permission: **Read Only** or **Read + Write**
- Admin can add an optional note explaining the access decision
- Approved users see **🏢 All Org Projects** in their dashboard
- Read = view only (no modifications possible)
- Write = can edit projects and vulnerabilities

### Deadline Management
- Projects past their end date show an **⏰ Engagement Overdue** banner
- Projects before their start date show a **Waiting for start date** banner
- Admin review notes shown prominently on the user's project info page

---

## 🔄 Complete Workflow

### For Normal Users
1. Register → verify email via OTP → login
2. **Raise New Request** — fill project details, select assigned admin
   - Your name and email auto-filled from your profile
3. Wait for **Admin Approval** (status: Request Pending)
4. Once approved → status: Waiting to start
5. Open project → **Start Pentest** (required before any vulnerability work)
6. **Add Vulnerabilities** — use CVSS calculator, attach POC screenshots
7. When done → **Finish Project** → write Executive Summary
8. Project moves to **Admin Review**
9. Receive final PDF + Word reports via email when admin approves

### For Admin
1. Login → **Admin Panel** opens automatically in sidebar
2. **Raised Requests** — review incoming requests → Approve or Reject
   - Approved → user can start their pentest
3. **Admin Review** — projects submitted by pentesters
   - **Approve & Email Reports** — generates PDF+Word, emails to pentester, marks Completed
   - **Request Changes** — adds a note, returns project to Running for fixes
4. **Org Access** — handle user requests for org-wide visibility
   - Choose Read Only or Read+Write, add optional note
5. **Users** — manage roles and account status
6. **Report Settings** — upload company logo, set colors and branding

---

## 📁 Folder Structure

```
VulnDossier/
├── main.py                          # Entry point — run this
├── requirements.txt
├── README.md
├── config/
│   ├── report_config.json           # Report branding (admin configures)
│   └── email_config.json            # SMTP settings (admin configures)
├── data/
│   └── vulndossier.db               # SQLite database (auto-created on first run)
├── auth/
│   └── auth_manager.py              # Login, register, password hashing
├── database/
│   └── db_manager.py                # All DB operations
├── ui/
│   ├── login_window.py              # Login + register + forgot password + OTP verify
│   ├── dashboard_window.py          # Main dashboard (role-aware)
│   ├── admin_panel_window.py        # Full admin panel
│   ├── project_work_window.py       # Project workspace with image display
│   ├── vuln_form_window.py          # CVSS calculator + POC image upload
│   ├── notification_panel.py        # 🔔 Bell + notification panel
│   ├── org_access_window.py         # User org access request form
│   ├── raise_request_window.py      # New/edit pentest request
│   ├── profile_window.py            # User profile management
│   ├── report_settings_window.py    # Report branding (admin only)
│   └── theme.py                     # Colors, fonts, style constants
├── core/
│   ├── cvss.py                      # CVSS v3.1 utilities (all 8 metrics)
│   ├── pdf_builder.py               # PDF report engine
│   └── docx_builder.py              # Word report engine
├── utils/
│   ├── security.py                  # Password policy, sanitization, lockout
│   ├── otp_manager.py               # OTP generation + email sending
│   ├── email_sender.py              # SMTP email (reports, OTP, notifications)
│   ├── report_builder.py            # Renumbers VUL IDs, orchestrates dual report
│   └── helpers.py                   # Formatting, OS utilities
├── output/                          # Generated reports (auto-organized)
│   └── ClientName/
│       └── ProjectName/
│           ├── Report_timestamp.pdf
│           └── Report_timestamp.docx
└── removed_vulnerabilities/         # Audit log for removed vulns
```

---

## 🛡️ Security

| Feature | Implementation |
|---------|----------------|
| Password hashing | SHA-256 with random 16-byte salt per user |
| Password policy | Min 8 chars, upper + lower + digit + special char |
| Strength meter | Live feedback during registration and changes |
| Brute-force | 5 attempts → 15-minute lockout |
| Input sanitization | XSS, SQL injection, path traversal all blocked |
| OTP codes | 6-char alphanumeric, cryptographically random, 10-min expiry |
| Email OTP | Sent from admin's SMTP over TLS (STARTTLS port 587) |
| Forgot password | OTP to registered email → set new password |
| Email change | OTP to new email address required to confirm |
| Account suspension | Admin can disable any user account instantly |
| Login audit log | Every attempt logged with timestamp |

---

## 📊 VUL ID Ordering

Vulnerabilities are always numbered **VUL-001 → highest severity first**:
- Adding VUL-003 (Critical) after VUL-001 (Medium) and VUL-002 (Low)?
  → All are renumbered: Critical=VUL-001, Medium=VUL-002, Low=VUL-003
- Removing a vulnerability? All others renumber immediately
- Reports always show Critical findings as VUL-001

---

## ❓ Troubleshooting

| Error | Fix |
|-------|-----|
| `python is not recognized` | Try `py main.py` or reinstall Python with "Add to PATH" ticked |
| `No module named customtkinter` | Run `pip install customtkinter reportlab python-docx Pillow` |
| `No module named tkinter` (Linux) | Run `sudo apt install python3-tk -y` |
| `externally-managed-environment` (Linux pip) | Add `--break-system-packages` to pip command |
| Email not sending | Check Admin Panel → Email Settings → Test Connection |
| Gmail auth failed | Use App Password (not your Gmail login password) |
| Images not showing in reports | Ensure image files still exist at their original paths |

---

## 🌐 Can This Go Online?

Yes — the core logic (auth, DB, reports) is framework-agnostic. To deploy as a web app:
1. Replace CustomTkinter GUI with **Flask** or **Django**
2. Replace SQLite with **PostgreSQL** or **MySQL**
3. Deploy on **VPS** (DigitalOcean, AWS, Azure) with Docker
4. Add HTTPS via **Let's Encrypt** (Certbot)
5. Use **Gunicorn + Nginx** for production serving

---

## ⚠️ Disclaimer

VulnDossier is for authorized penetration testing only. Always obtain written permission before testing any system you do not own. The author accepts no liability for unauthorized use.

---

## 👤 Author

**Harsh Goyal** — Penetration Tester | CEH | CCNA  
🔗 [LinkedIn](https://www.linkedin.com/in/harsh-goyal-cybersecurity-engineer-cybersecurity-engineer/)  
🐙 [GitHub](https://github.com/HarshG404)

If this tool saves you time on reporting, a ⭐ on the repo is appreciated!

---

## 📄 License

MIT License — free to use, modify, and distribute. See [LICENSE](LICENSE) for details.
