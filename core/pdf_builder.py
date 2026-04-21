"""
pdf_builder.py — PDF report with:
  • Company branding from config (logo, colors, company name)
  • Clickable Table of Contents on page 2 (anchors to each section)
  • Each vulnerability on its own page
  • All 8 CVSS v3.1 metrics (incl. Integrity & Availability)
  • Configurable header/footer on every page
"""
import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether, Image
)
from reportlab.pdfgen import canvas as pdfcanvas

from core.cvss import cvss_breakdown, sev_badge_rgb, sev_text_rgb, sev_bg_rgb
from config.config_manager import load_config, hex_to_rgb

PAGE_W, PAGE_H = A4
MARGIN = 20 * mm


def _c(h, fallback="#1D9E75"):
    try:
        r, g, b = hex_to_rgb(h)
        return colors.Color(r/255, g/255, b/255)
    except Exception:
        return colors.HexColor(fallback)


def _sev_badge(s): r,g,b=sev_badge_rgb(s); return colors.Color(r/255,g/255,b/255)
def _sev_bg(s):    r,g,b=sev_bg_rgb(s);    return colors.Color(r/255,g/255,b/255)
def _sev_text(s):  r,g,b=sev_text_rgb(s);  return colors.Color(r/255,g/255,b/255)

BORDER = colors.HexColor("#D0D7DE")
LIGHT  = colors.HexColor("#F6F8FA")
WHITE  = colors.white
DARK_T = colors.HexColor("#1F2328")
MUTED  = colors.HexColor("#636E7B")


def _styles(cfg):
    cov_txt = _c(cfg.get("colors",{}).get("cover_text","#FFFFFF"))
    return {
        "cover_title": ParagraphStyle("ct", fontName="Helvetica-Bold", fontSize=26,
            textColor=cov_txt, leading=32, spaceAfter=6),
        "cover_sub": ParagraphStyle("cs", fontName="Helvetica", fontSize=13,
            textColor=colors.Color(0.63,0.67,0.72), leading=18, spaceAfter=4),
        "cover_meta": ParagraphStyle("cm", fontName="Helvetica", fontSize=10,
            textColor=colors.Color(0.55,0.58,0.62), leading=16, spaceAfter=2),
        "h1": ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=16,
            textColor=DARK_T, leading=20, spaceBefore=14, spaceAfter=8),
        "body": ParagraphStyle("body", fontName="Helvetica", fontSize=10,
            textColor=DARK_T, leading=15, spaceAfter=4, alignment=TA_JUSTIFY),
        "label": ParagraphStyle("lbl", fontName="Helvetica-Bold", fontSize=9,
            textColor=MUTED, leading=12, spaceAfter=2, spaceBefore=6),
        "mono": ParagraphStyle("mono", fontName="Courier", fontSize=9,
            textColor=DARK_T, leading=13, spaceAfter=2,
            backColor=LIGHT, borderPad=4),
        "finding_title": ParagraphStyle("ft", fontName="Helvetica-Bold", fontSize=13,
            textColor=DARK_T, leading=17, spaceAfter=2),
        "toc_entry": ParagraphStyle("toc", fontName="Helvetica", fontSize=10,
            textColor=DARK_T, leading=20, leftIndent=8),
        "toc_head": ParagraphStyle("toch", fontName="Helvetica-Bold", fontSize=11,
            textColor=DARK_T, leading=18, spaceBefore=8),
    }


class BrandedCanvas(pdfcanvas.Canvas):
    def __init__(self, filename, cfg, meta, **kwargs):
        super().__init__(filename, **kwargs)
        self.cfg  = cfg
        self.meta = meta
        self._saved = []

    def showPage(self):
        self._saved.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        n = len(self._saved)
        for i, state in enumerate(self._saved):
            self.__dict__.update(state)
            self._decorate(i+1, n)
            super().showPage()
        super().save()

    def _sub(self, tmpl, page, total):
        company = self.cfg.get("company", {})
        return (tmpl or "") \
            .replace("{client_name}",    self.meta.get("client_name","")) \
            .replace("{assessment_type}",self.meta.get("project_type","")) \
            .replace("{company_name}",   company.get("name","")) \
            .replace("{date}",           datetime.today().strftime("%Y-%m-%d")) \
            .replace("{page}",           str(page)) \
            .replace("{total_pages}",    str(total))

    def _decorate(self, page_num, total):
        if page_num == 1:
            return
        cfg = self.cfg
        hf  = cfg.get("header_footer", {})
        w, h = A4
        self.saveState()

        try:
            hdr_bg = colors.HexColor(cfg.get("colors",{}).get("header_bg","#0D1117"))
        except Exception:
            hdr_bg = colors.HexColor("#0D1117")

        # ── Header ──
        if hf.get("show_header", True):
            self.setFillColor(hdr_bg)
            self.rect(0, h-12*mm, w, 12*mm, fill=1, stroke=0)
            self.setFillColor(colors.Color(0.55,0.58,0.62))
            self.setFont("Helvetica", 8)
            self.drawString(MARGIN, h-7*mm,
                            self._sub(hf.get("header_left","{client_name}"), page_num, total))
            self.drawRightString(w-MARGIN, h-7*mm,
                                 self._sub(hf.get("header_right","{assessment_type}"), page_num, total))
            # Logo
            logo = cfg.get("branding",{}).get("logo_path","")
            if logo and os.path.exists(logo):
                try:
                    from PIL import Image as PILImage
                    pil = PILImage.open(logo)
                    asp = pil.width / pil.height
                    lh  = 8*mm
                    lw  = lh * asp
                    self.drawImage(logo, w/2-lw/2, h-11*mm, width=lw, height=lh, mask="auto")
                except Exception:
                    pass

        # ── Footer ──
        if hf.get("show_footer", True):
            self.setStrokeColor(BORDER)
            self.setLineWidth(0.5)
            self.line(MARGIN, 12*mm, w-MARGIN, 12*mm)
            self.setFillColor(colors.Color(0.39,0.43,0.48))
            self.setFont("Helvetica", 8)
            self.drawString(MARGIN, 7*mm,
                            self._sub(hf.get("footer_left","CONFIDENTIAL — {client_name}"), page_num, total))
            self.drawCentredString(w/2, 7*mm,
                                   self._sub(hf.get("footer_center","{company_name}"), page_num, total))
            self.drawRightString(w-MARGIN, 7*mm,
                                 self._sub(hf.get("footer_right","Page {page} of {total_pages}"), page_num, total))
        self.restoreState()


def _build_cover(story, S, cfg, meta):
    company  = cfg.get("company", {})
    cover_c  = cfg.get("cover_page", {})
    branding = cfg.get("branding", {})
    accent   = cfg.get("colors",{}).get("accent","#1D9E75")
    cover_bg = cfg.get("colors",{}).get("cover_bg","#0D1117")
    W        = PAGE_W - 2*MARGIN

    rows = []

    # Logo
    logo = branding.get("logo_path","")
    if cover_c.get("show_logo",True) and logo and os.path.exists(logo):
        try:
            lw = branding.get("logo_width_mm",40)*mm
            lh = branding.get("logo_height_mm",20)*mm
            rows.append([Image(logo, width=lw, height=lh)])
            rows.append([Spacer(1,4*mm)])
        except Exception:
            pass

    # Company
    if cover_c.get("show_company_name",True) and company.get("name"):
        rows.append([Paragraph(
            f"<font color='{accent}'><b>{company['name']}</b></font>",
            ParagraphStyle("cn",fontName="Helvetica-Bold",fontSize=14,
                textColor=WHITE,leading=18))])
    if cover_c.get("show_company_tagline",True) and company.get("tagline"):
        rows.append([Paragraph(company["tagline"],
            ParagraphStyle("ct2",fontName="Helvetica",fontSize=10,
                textColor=colors.Color(0.55,0.58,0.62),leading=14))])
    rows.append([Spacer(1,8*mm)])

    # Classification banner
    if cover_c.get("classification_banner",True):
        cl = meta.get("classification","CONFIDENTIAL")
        rows.append([Paragraph(
            f"<font color='#FF7B72'>■</font>  {cl}",
            ParagraphStyle("clf",fontName="Helvetica-Bold",fontSize=10,
                textColor=colors.Color(1,0.48,0.44),leading=14))])
        rows.append([Spacer(1,4*mm)])

    # Assessment type / custom title
    title = (cover_c.get("custom_cover_title") or
             meta.get("project_type","Penetration Test Report")).upper()
    rows.append([Paragraph(f"<font color='{accent}'>■ </font>{title}", S["cover_sub"])])
    rows.append([Spacer(1,4*mm)])
    rows.append([Paragraph(meta.get("client_name","Client Report"), S["cover_title"])])
    rows.append([Spacer(1,8*mm)])

    for k,v in [
        ("Assessor",  meta.get("pentester_name","")),
        ("Scope",     meta.get("scope","")),
        ("Period",    f"{meta.get('start_date','')} → {meta.get('end_date','')}"),
        ("Classification", meta.get("classification","CONFIDENTIAL")),
    ]:
        if v: rows.append([Paragraph(f"<font color='#636E7B'>{k}:</font>  {v}", S["cover_meta"])])

    if cover_c.get("show_report_version",True):
        rows.append([Paragraph(
            f"<font color='#636E7B'>Version:</font>  {meta.get('version','1.0')}  "
            f"  <font color='#636E7B'>Date:</font>  {datetime.today().strftime('%B %d, %Y')}",
            S["cover_meta"])])

    if cover_c.get("custom_footer_note"):
        rows.append([Spacer(1,6*mm)])
        rows.append([Paragraph(cover_c["custom_footer_note"],
            ParagraphStyle("cfn",fontName="Helvetica-Oblique",fontSize=9,
                textColor=colors.Color(0.55,0.58,0.62),leading=13))])

    story.append(HRFlowable(width="100%", thickness=4, color=colors.HexColor(accent), spaceAfter=0))
    t = Table([[r[0]] for r in rows], colWidths=[W])
    t.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,-1),colors.HexColor(cover_bg)),
        ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),
        ("LEFTPADDING",(0,0),(-1,-1),16),("RIGHTPADDING",(0,0),(-1,-1),16),
    ]))
    story.append(t)
    story.append(HRFlowable(width="100%", thickness=4, color=colors.HexColor(accent), spaceBefore=0))
    story.append(PageBreak())


def _build_toc(story, S, findings, cfg):
    accent = cfg.get("colors",{}).get("accent","#1D9E75")
    story.append(Paragraph("Table of Contents", S["h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=BORDER, spaceAfter=10))

    for num, title in [("1","Executive Summary"),("2","Vulnerability Summary"),
                       ("3","Findings Overview"),("4","Detailed Findings")]:
        anchor = title.replace(" ","_")
        story.append(Paragraph(
            f'<font color="#636E7B">{num}.</font>  '
            f'<a href="#{anchor}"><font color="#58A6FF">{title}</font></a>',
            S["toc_entry"]
        ))

    story.append(Spacer(1,4*mm))
    story.append(Paragraph("Vulnerabilities", S["toc_head"]))
    story.append(Spacer(1,2*mm))

    W = PAGE_W - 2*MARGIN
    for i, f in enumerate(findings):
        sev    = f.get("severity","Low")
        vid    = f.get("vuln_id", f"VUL-{i+1:03d}")
        anchor = f"vuln_{vid.replace('-','_')}"

        row = [[
            Paragraph(f'<font color="#636E7B"><b>{vid}</b></font>',
                ParagraphStyle("tv",fontName="Helvetica-Bold",fontSize=9,
                    textColor=MUTED,leading=18)),
            Paragraph(
                f'<a href="#{anchor}"><font color="#58A6FF">{f.get("title","")}</font></a>',
                ParagraphStyle("tt",fontName="Helvetica",fontSize=10,
                    textColor=DARK_T,leading=18)),
            Paragraph(f"<b>{sev}</b>",
                ParagraphStyle("ts",fontName="Helvetica-Bold",fontSize=9,
                    textColor=_sev_text(sev),leading=18,alignment=TA_CENTER)),
            Paragraph(str(f.get("cvss_score","")),
                ParagraphStyle("tc",fontName="Helvetica-Bold",fontSize=9,
                    textColor=_sev_text(sev),leading=18,alignment=TA_CENTER)),
        ]]
        t = Table(row, colWidths=[55, W-160, 65, 40])
        bg = LIGHT if i%2==0 else WHITE
        t.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,-1),bg),
            ("BACKGROUND",(2,0),(2,-1),_sev_bg(sev)),
            ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
            ("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6),
            ("LEFTPADDING",(0,0),(-1,-1),8),("RIGHTPADDING",(0,0),(-1,-1),8),
            ("LINEBELOW",(0,0),(-1,-1),0.3,BORDER),
        ]))
        story.append(t)
    story.append(PageBreak())


def _build_summary(story, S, findings, cfg):
    counts  = {s:0 for s in ["Critical","High","Medium","Low","Informational"]}
    for f in findings: counts[f.get("severity","Low")] = counts.get(f.get("severity","Low"),0)+1
    overall = next((s for s in ["Critical","High","Medium","Low","Informational"] if counts.get(s,0)>0), "Informational")
    W       = PAGE_W - 2*MARGIN

    story.append(Paragraph('<a name="Vulnerability_Summary"></a>Vulnerability Summary', S["h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=BORDER, spaceAfter=8))

    cards = []
    for sev in ["Critical","High","Medium","Low"]:
        c = Table([
            [Paragraph(f"<b>{sev}</b>",ParagraphStyle("sl",fontName="Helvetica-Bold",
                fontSize=9,textColor=_sev_text(sev),leading=12,alignment=TA_CENTER))],
            [Paragraph(f"<b>{counts.get(sev,0)}</b>",ParagraphStyle("sv",fontName="Helvetica-Bold",
                fontSize=24,textColor=_sev_text(sev),leading=28,alignment=TA_CENTER))],
            [Paragraph("findings",ParagraphStyle("ss",fontName="Helvetica",
                fontSize=8,textColor=_sev_text(sev),leading=10,alignment=TA_CENTER))],
        ], colWidths=[W/4-4])
        c.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,-1),_sev_bg(sev)),
            ("BOX",(0,0),(-1,-1),0.5,_sev_badge(sev)),
            ("TOPPADDING",(0,0),(-1,-1),8),("BOTTOMPADDING",(0,0),(-1,-1),8),
        ]))
        cards.append(c)
    row = Table([cards], colWidths=[W/4]*4)
    row.setStyle(TableStyle([("LEFTPADDING",(0,0),(-1,-1),2),("RIGHTPADDING",(0,0),(-1,-1),2)]))
    story.append(row)
    story.append(Spacer(1,4*mm))

    or_t = Table([[
        Paragraph("Overall Risk:", ParagraphStyle("or",fontName="Helvetica-Bold",
            fontSize=11,textColor=DARK_T,leading=14)),
        Paragraph(f"<b>{overall}</b>",ParagraphStyle("orv",fontName="Helvetica-Bold",
            fontSize=11,textColor=_sev_text(overall),leading=14)),
        Paragraph(f"Total: <b>{len(findings)}</b>",ParagraphStyle("ort",fontName="Helvetica",
            fontSize=11,textColor=DARK_T,leading=14)),
    ]], colWidths=[110,70,W-180])
    or_t.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,-1),LIGHT),("BOX",(0,0),(-1,-1),0.5,BORDER),
        ("TOPPADDING",(0,0),(-1,-1),8),("BOTTOMPADDING",(0,0),(-1,-1),8),
        ("LEFTPADDING",(0,0),(-1,-1),12),("VALIGN",(0,0),(-1,-1),"MIDDLE"),
    ]))
    story.append(or_t)
    story.append(Spacer(1,4*mm))


def _build_overview(story, S, findings, cfg):
    DARK = _c(cfg.get("colors",{}).get("header_bg","#0D1117"))
    story.append(Paragraph('<a name="Findings_Overview"></a>Findings Overview', S["h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=BORDER, spaceAfter=8))

    td = [["ID","Title","Severity","CVSS","Affected"]]
    for f in findings:
        sev = f.get("severity","Low")
        td.append([
            Paragraph(f.get("vuln_id",""),ParagraphStyle("tc",fontName="Helvetica-Bold",
                fontSize=9,textColor=MUTED,leading=12)),
            Paragraph(f.get("title",""),ParagraphStyle("tt",fontName="Helvetica",
                fontSize=9,textColor=DARK_T,leading=12)),
            Paragraph(f"<b>{sev}</b>",ParagraphStyle("ts",fontName="Helvetica-Bold",
                fontSize=9,textColor=_sev_text(sev),leading=12,alignment=TA_CENTER)),
            Paragraph(str(f.get("cvss_score","")),ParagraphStyle("tcs",fontName="Helvetica-Bold",
                fontSize=9,textColor=_sev_text(sev),leading=12,alignment=TA_CENTER)),
            Paragraph(str(f.get("affected",""))[:55],ParagraphStyle("ta",fontName="Helvetica",
                fontSize=8,textColor=MUTED,leading=11)),
        ])
    ov = Table(td, colWidths=[45,155,55,35,165], repeatRows=1)
    st = [
        ("BACKGROUND",(0,0),(-1,0),DARK),("TEXTCOLOR",(0,0),(-1,0),WHITE),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,0),9),
        ("TOPPADDING",(0,0),(-1,0),8),("BOTTOMPADDING",(0,0),(-1,0),8),
        ("ALIGN",(2,0),(3,-1),"CENTER"),("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE,LIGHT]),
        ("TOPPADDING",(0,1),(-1,-1),6),("BOTTOMPADDING",(0,1),(-1,-1),6),
        ("LEFTPADDING",(0,0),(-1,-1),8),("RIGHTPADDING",(0,0),(-1,-1),8),
        ("LINEBELOW",(0,0),(-1,-1),0.3,BORDER),("BOX",(0,0),(-1,-1),0.5,BORDER),
    ]
    for i,f in enumerate(findings,1):
        st.append(("BACKGROUND",(2,i),(2,i),_sev_bg(f.get("severity","Low"))))
    ov.setStyle(TableStyle(st))
    story.append(ov)
    story.append(PageBreak())


def _build_finding(story, S, f, cfg, is_first=False):
    sev    = f.get("severity","Low")
    vid    = f.get("vuln_id","")
    anchor = f"vuln_{vid.replace('-','_')}"
    W      = PAGE_W - 2*MARGIN

    elems = []

    # Header band with anchor
    hdr = Table([[
        Paragraph(f'<a name="{anchor}"></a>{vid} — {f.get("title","")}', S["finding_title"]),
        Paragraph(f"<b>{sev}</b>  {f.get('cvss_score','')}",
            ParagraphStyle("sp",fontName="Helvetica-Bold",fontSize=11,
                textColor=_sev_text(sev),leading=14,alignment=TA_RIGHT)),
    ]], colWidths=[W-80,80])
    hdr.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,-1),_sev_bg(sev)),
        ("BOX",(0,0),(-1,-1),1,_sev_badge(sev)),
        ("TOPPADDING",(0,0),(-1,-1),10),("BOTTOMPADDING",(0,0),(-1,-1),10),
        ("LEFTPADDING",(0,0),(-1,-1),12),("RIGHTPADDING",(0,0),(-1,-1),12),
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
    ]))
    elems.append(hdr)
    elems.append(Spacer(1,2*mm))

    # CVSS vector text
    if f.get("cvss_vector"):
        elems.append(Paragraph(f"Vector: {f['cvss_vector']}",
            ParagraphStyle("cv",fontName="Courier",fontSize=8,
                textColor=MUTED,leading=12)))
        elems.append(Spacer(1,2*mm))

    # All 8 CVSS metrics in 2 rows of 4
    breakdown = cvss_breakdown(f.get("cvss_vector",""))
    if breakdown:
        items = list(breakdown.items())
        for chunk in [items[:4], items[4:]]:
            if not chunk: continue
            cw = (W - 4*len(chunk)) / len(chunk)
            cells = []
            for label,val in chunk:
                c = Table([
                    [Paragraph(label,ParagraphStyle("cl",fontName="Helvetica",fontSize=7,
                        textColor=MUTED,leading=9,alignment=TA_CENTER))],
                    [Paragraph(f"<b>{val}</b>",ParagraphStyle("cv2",fontName="Helvetica-Bold",
                        fontSize=9,textColor=DARK_T,leading=11,alignment=TA_CENTER))],
                ], colWidths=[cw])
                c.setStyle(TableStyle([
                    ("BACKGROUND",(0,0),(-1,-1),LIGHT),
                    ("BOX",(0,0),(-1,-1),0.3,BORDER),
                    ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),
                ]))
                cells.append(c)
            br = Table([cells], colWidths=[(W/len(chunk))]*len(chunk))
            br.setStyle(TableStyle([
                ("LEFTPADDING",(0,0),(-1,-1),2),("RIGHTPADDING",(0,0),(-1,-1),2)]))
            elems.append(br)
            elems.append(Spacer(1,1*mm))

    elems.append(Spacer(1,2*mm))

    def sec(label, text, mono=False):
        if not text or str(text).strip() in ("","NA","N/A"): return
        elems.append(Paragraph(label, S["label"]))
        for line in str(text).split("\n"):
            if line.strip():
                elems.append(Paragraph(line.strip(), S["mono"] if mono else S["body"]))

    sec("Affected Component",  f.get("affected",""))
    sec("Description",         f.get("description",""))
    sec("Steps to Reproduce",  f.get("steps_to_reproduce",""), mono=True)

    # ── POC Images — embedded under Steps to Reproduce ──
    import json as _j, os as _o
    _poc = []
    try:
        _poc = _j.loads(f.get("poc_images","[]") or "[]")
    except Exception:
        _poc = []
    if _poc:
        elems.append(Paragraph("POC Screenshots / Evidence", S["label"]))
        for _img in _poc:
            if _img and _o.path.exists(_img):
                try:
                    from PIL import Image as _PIL
                    _pil = _PIL.open(_img)
                    _pw, _ph = _pil.size
                    _mw = W - 4*mm
                    _mh = 260.0   # max height in points
                    _scale = min(1.0, _mw / _pw, _mh / _ph)
                    _iw = _pw * _scale
                    _ih = _ph * _scale
                    from reportlab.platypus import Image as _RLI
                    elems.append(_RLI(_img, width=_iw, height=_ih))
                    elems.append(Paragraph(
                        f"<i>Fig: {_o.path.basename(_img)}</i>",
                        ParagraphStyle("poc_cap", fontName="Helvetica-Oblique",
                            fontSize=8, textColor=MUTED, leading=10, spaceAfter=4)
                    ))
                    elems.append(Spacer(1, 2*mm))
                except Exception as _e:
                    elems.append(Paragraph(
                        f"[{_o.path.basename(_img)} — could not load: {_e}]",
                        ParagraphStyle("poc_err", fontName="Helvetica-Oblique",
                            fontSize=8, textColor=MUTED, leading=10)
                    ))

    sec("Impact",              f.get("impact",""))
    sec("Recommendation",      f.get("recommendations",""))
    if f.get("reference") and f.get("reference") not in ("NA","N/A"):
        sec("References", f.get("reference",""))

    elems.append(Spacer(1,4*mm))

    story.append(KeepTogether(elems[:6]))
    for e in elems[6:]:
        story.append(e)


def build_pdf(report_data: dict, output_path: str) -> str:
    cfg      = load_config()
    meta     = report_data.get("meta", {})
    findings = report_data.get("findings", [])
    exec_sum = report_data.get("executive_summary", "")
    struct   = cfg.get("report_structure", {})

    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)

    def make_canvas(filename, **kwargs):
        return BrandedCanvas(filename, cfg, meta, pagesize=A4)

    doc = SimpleDocTemplate(output_path, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN+8*mm, bottomMargin=MARGIN+4*mm,
        title=f"{meta.get('client_name','')} — Pentest Report",
        author=meta.get("pentester_name",""))

    S = _styles(cfg)
    story = []

    _build_cover(story, S, cfg, meta)

    if struct.get("show_toc", True):
        _build_toc(story, S, findings, cfg)

    if struct.get("show_executive_summary", True):
        story.append(Paragraph('<a name="Executive_Summary"></a>Executive Summary', S["h1"]))
        story.append(HRFlowable(width="100%", thickness=1, color=BORDER, spaceAfter=8))
        for line in exec_sum.split("\n"):
            if line.strip():
                story.append(Paragraph(line.strip(), S["body"]))
        story.append(Spacer(1,6*mm))

    if struct.get("show_summary_cards", True):
        _build_summary(story, S, findings, cfg)

    if struct.get("show_findings_table", True):
        _build_overview(story, S, findings, cfg)

    if struct.get("show_detailed_findings", True):
        story.append(Paragraph('<a name="Detailed_Findings"></a>Detailed Findings', S["h1"]))
        story.append(HRFlowable(width="100%", thickness=1, color=BORDER, spaceAfter=12))
        new_page = struct.get("each_vuln_new_page", True)
        for i, f in enumerate(findings):
            if i > 0 and new_page:
                story.append(PageBreak())
            _build_finding(story, S, f, cfg, is_first=(i==0))

    if struct.get("show_disclaimer", True):
        story.append(PageBreak())
        story.append(Paragraph("Disclaimer & Notes", S["h1"]))
        story.append(HRFlowable(width="100%", thickness=1, color=BORDER, spaceAfter=8))
        disc = cfg.get("disclaimer", {})
        story.append(Paragraph(disc.get("text", "This report is confidential."), S["body"]))
        company = cfg.get("company", {})
        if company.get("name"):
            story.append(Spacer(1,4*mm))
            story.append(Paragraph(
                f"Prepared by: {company['name']}  |  {company.get('website','')}  |  {company.get('email','')}",
                ParagraphStyle("cp",fontName="Helvetica",fontSize=9,textColor=MUTED,leading=13)))
        # POC note removed — images are embedded in findings

    doc.build(story, canvasmaker=make_canvas)
    return output_path
