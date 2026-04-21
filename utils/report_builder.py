"""
report_builder.py — Orchestrates PDF + DOCX report generation from DB project data
"""
import os
from datetime import datetime
from database.db_manager import get_project_by_id, get_vulnerabilities
from core.pdf_builder import build_pdf
from core.docx_builder import build_docx

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}


def _safe_name(name: str) -> str:
    return "".join(c if c.isalnum() or c in "._- " else "_" for c in name).strip()


def _build_report_data(project: dict, findings: list) -> dict:
    # Sort by severity (Critical first) but re-number display IDs to match sorted order
    sorted_findings = sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.get(f.get("severity", "Low"), 0),
        reverse=True
    )
    # Re-assign VUL IDs to match severity-sorted order in the report
    for i, f in enumerate(sorted_findings):
        f = dict(f)  # don't mutate DB data
        f["vuln_id"] = f"VUL-{i+1:03d}"
        sorted_findings[i] = f
    return {
        "meta": {
            "client_name":      project.get("client_name", ""),
            "project_name":     project.get("project_name", ""),
            "project_type":     project.get("project_type", ""),
            "scope":            project.get("scope", ""),
            "start_date":       project.get("start_date", ""),
            "end_date":         project.get("end_date", ""),
            "pentester_name":   project.get("pentester_name", ""),
            "pentester_email":  project.get("pentester_email", ""),
            "classification":   project.get("classification", "CONFIDENTIAL"),
            "criticality":      project.get("criticality", ""),
            "reason":           project.get("reason", ""),
            "walkthrough_done": project.get("walkthrough_done", ""),
            "manager_email":    project.get("manager_email", ""),
            "version":          "1.0",
        },
        "executive_summary": project.get("executive_summary", ""),
        "findings":          sorted_findings,
    }


def get_output_folder(project: dict) -> str:
    base = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "output"
    )
    client_folder  = _safe_name(project.get("client_name", "Unknown_Client"))
    project_folder = _safe_name(project.get("project_name", "Unknown_Project"))
    folder = os.path.join(base, client_folder, project_folder)
    os.makedirs(folder, exist_ok=True)
    return folder


def generate_reports(project_id: int, report_name: str = None) -> dict:
    """
    Generate both PDF and DOCX reports for a project.
    Returns dict with paths to generated files.
    """
    project  = get_project_by_id(project_id)
    findings = get_vulnerabilities(project_id)

    if not project:
        raise ValueError(f"Project ID {project_id} not found.")

    report_data = _build_report_data(project, findings)
    folder      = get_output_folder(project)

    date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    if report_name:
        safe_rname = _safe_name(report_name)
    else:
        safe_rname = _safe_name(project.get("project_name", "Report"))

    pdf_path  = os.path.join(folder, f"{safe_rname}_{date_str}.pdf")
    docx_path = os.path.join(folder, f"{safe_rname}_{date_str}.docx")

    build_pdf(report_data, pdf_path)
    build_docx(report_data, docx_path)

    return {
        "pdf":    pdf_path,
        "docx":   docx_path,
        "folder": folder,
    }
