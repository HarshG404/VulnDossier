"""
cvss.py — CVSS v3.1 utilities (severity labels, colors, full vector breakdown)
"""

SEVERITY_CONFIG = {
    "Critical":      {"badge_rgb": (220, 53, 69),   "text_rgb": (123, 0, 0),   "bg_rgb": (253, 234, 234)},
    "High":          {"badge_rgb": (253, 126, 20),  "text_rgb": (125, 60, 0),  "bg_rgb": (254, 243, 226)},
    "Medium":        {"badge_rgb": (255, 193, 7),   "text_rgb": (122, 101, 0), "bg_rgb": (255, 253, 231)},
    "Low":           {"badge_rgb": (40, 167, 69),   "text_rgb": (26, 92, 26),  "bg_rgb": (234, 246, 234)},
    "Informational": {"badge_rgb": (13, 110, 253),  "text_rgb": (12, 60, 110), "bg_rgb": (232, 241, 251)},
}


def score_to_severity(score: float) -> str:
    score = float(score)
    if score >= 9.0:  return "Critical"
    if score >= 7.0:  return "High"
    if score >= 4.0:  return "Medium"
    if score > 0.0:   return "Low"
    return "Informational"


def get_config(severity: str) -> dict:
    return SEVERITY_CONFIG.get(severity, SEVERITY_CONFIG["Informational"])


def sev_badge_rgb(sev: str): return get_config(sev)["badge_rgb"]
def sev_text_rgb(sev: str):  return get_config(sev)["text_rgb"]
def sev_bg_rgb(sev: str):    return get_config(sev)["bg_rgb"]


def cvss_breakdown(vector: str) -> dict:
    """
    Parse CVSS:3.1 vector string → dict of {full_metric_name: human_value}.
    All 8 base metrics are included, ensuring Integrity and Availability are present.
    """
    if not vector or not vector.startswith("CVSS:"):
        return {}

    labels = {
        "AV": {"N": "Network",   "A": "Adjacent", "L": "Local",    "P": "Physical"},
        "AC": {"L": "Low",       "H": "High"},
        "PR": {"N": "None",      "L": "Low",       "H": "High"},
        "UI": {"N": "None",      "R": "Required"},
        "S":  {"U": "Unchanged", "C": "Changed"},
        "C":  {"N": "None",      "L": "Low",       "H": "High"},
        "I":  {"N": "None",      "L": "Low",       "H": "High"},
        "A":  {"N": "None",      "L": "Low",       "H": "High"},
    }
    full_names = {
        "AV": "Attack Vector",
        "AC": "Attack Complexity",
        "PR": "Privileges Required",
        "UI": "User Interaction",
        "S":  "Scope",
        "C":  "Confidentiality",
        "I":  "Integrity",       # ← Always present now
        "A":  "Availability",    # ← Always present now
    }

    try:
        result = {}
        for part in vector.split("/")[1:]:
            if ":" not in part:
                continue
            key, val = part.split(":", 1)
            if key in labels:
                result[full_names[key]] = labels[key].get(val, val)
        # Ensure all 8 metrics appear (fill N/A for any missing)
        for k, fname in full_names.items():
            if fname not in result:
                result[fname] = "N/A"
        return result
    except Exception:
        return {}
