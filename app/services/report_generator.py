"""
report_generator.py
~~~~~~~~~~~~~~~~~~~~
Generates a professional multi-page PDF security report using ReportLab.

Pages
-----
  1. Cover page       — title, date, classification, summary numbers
  2. Executive Summary — business-risk narrative, top risks, patch stats
  3. Severity Chart    — donut-style bar breakdown (ReportLab drawing)
  4. Asset Risk Ranking — ranked table with risk scores and criticality
  5. Detailed Findings — per-asset CVE breakdown with CVSS, CWE, patch status
  6. Recommendations   — auto-generated based on top findings
"""

import io
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether,
)
from reportlab.graphics.shapes import Drawing, Rect, String, Line
from reportlab.graphics import renderPDF
from reportlab.platypus.flowables import Flowable

# ── Colour palette (matches VaultScan dark theme, printed light) ──────────
C_PURPLE      = colors.HexColor("#6d28d9")
C_PURPLE_LIGHT= colors.HexColor("#ede9fe")
C_RED         = colors.HexColor("#dc2626")
C_RED_LIGHT   = colors.HexColor("#fee2e2")
C_ORANGE      = colors.HexColor("#ea580c")
C_ORANGE_LIGHT= colors.HexColor("#ffedd5")
C_YELLOW      = colors.HexColor("#ca8a04")
C_YELLOW_LIGHT= colors.HexColor("#fef9c3")
C_GREEN       = colors.HexColor("#16a34a")
C_GREEN_LIGHT = colors.HexColor("#dcfce7")
C_DARK        = colors.HexColor("#1e1b4b")
C_GRAY        = colors.HexColor("#6b7280")
C_LIGHT_GRAY  = colors.HexColor("#f3f4f6")
C_WHITE       = colors.white
C_BLACK       = colors.HexColor("#111827")

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm


def _severity_color(sev):
    m = {
        "critical": (C_RED,    C_RED_LIGHT),
        "high":     (C_ORANGE, C_ORANGE_LIGHT),
        "medium":   (C_YELLOW, C_YELLOW_LIGHT),
        "low":      (C_GREEN,  C_GREEN_LIGHT),
    }
    return m.get((sev or "").lower(), (C_GRAY, C_LIGHT_GRAY))


# ── Custom styles ─────────────────────────────────────────────────────────
def _styles():
    return {
        "cover_title": ParagraphStyle(
            "cover_title", fontSize=32, textColor=C_WHITE,
            fontName="Helvetica-Bold", leading=38, alignment=TA_LEFT,
        ),
        "cover_sub": ParagraphStyle(
            "cover_sub", fontSize=13, textColor=colors.HexColor("#c4b5fd"),
            fontName="Helvetica", leading=18, alignment=TA_LEFT,
        ),
        "cover_meta": ParagraphStyle(
            "cover_meta", fontSize=10, textColor=colors.HexColor("#a78bfa"),
            fontName="Helvetica", leading=14, alignment=TA_LEFT,
        ),
        "section_title": ParagraphStyle(
            "section_title", fontSize=16, textColor=C_DARK,
            fontName="Helvetica-Bold", leading=20, spaceBefore=6,
        ),
        "subsection": ParagraphStyle(
            "subsection", fontSize=12, textColor=C_PURPLE,
            fontName="Helvetica-Bold", leading=16, spaceBefore=8,
        ),
        "body": ParagraphStyle(
            "body", fontSize=9.5, textColor=C_BLACK,
            fontName="Helvetica", leading=14, spaceBefore=3,
        ),
        "body_small": ParagraphStyle(
            "body_small", fontSize=8.5, textColor=C_GRAY,
            fontName="Helvetica", leading=12,
        ),
        "table_header": ParagraphStyle(
            "table_header", fontSize=8, textColor=C_WHITE,
            fontName="Helvetica-Bold", alignment=TA_CENTER,
        ),
        "table_cell": ParagraphStyle(
            "table_cell", fontSize=8.5, textColor=C_BLACK,
            fontName="Helvetica", leading=12,
        ),
        "table_cell_mono": ParagraphStyle(
            "table_cell_mono", fontSize=8, textColor=C_DARK,
            fontName="Courier", leading=11,
        ),
        "caption": ParagraphStyle(
            "caption", fontSize=8, textColor=C_GRAY,
            fontName="Helvetica", alignment=TA_CENTER, spaceBefore=2,
        ),
        "footer": ParagraphStyle(
            "footer", fontSize=7.5, textColor=C_GRAY,
            fontName="Helvetica", alignment=TA_CENTER,
        ),
    }


# ── Page template callbacks ───────────────────────────────────────────────
def _header_footer(canvas, doc):
    canvas.saveState()
    w, h = A4

    if doc.page == 1:
        # Cover — full dark background
        canvas.setFillColor(C_DARK)
        canvas.rect(0, 0, w, h, fill=1, stroke=0)
        # Purple accent bar
        canvas.setFillColor(C_PURPLE)
        canvas.rect(0, h - 8*mm, w, 8*mm, fill=1, stroke=0)
        canvas.restoreState()
        return

    # Inner pages — top bar
    canvas.setFillColor(C_DARK)
    canvas.rect(0, h - 12*mm, w, 12*mm, fill=1, stroke=0)

    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(C_WHITE)
    canvas.drawString(MARGIN, h - 8*mm, "SECURITY VULNERABILITY ASSESSMENT REPORT")
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(w - MARGIN, h - 8*mm,
                           datetime.now().strftime("%d %b %Y"))

    # Footer line
    canvas.setStrokeColor(colors.HexColor("#e5e7eb"))
    canvas.setLineWidth(0.5)
    canvas.line(MARGIN, 10*mm, w - MARGIN, 10*mm)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(C_GRAY)
    canvas.drawString(MARGIN, 6*mm, "CONFIDENTIAL — For authorised recipients only")
    canvas.drawRightString(w - MARGIN, 6*mm, f"Page {doc.page}")

    canvas.restoreState()


# ── Severity bar chart (pure ReportLab drawing) ───────────────────────────
def _severity_chart(counts: dict) -> Drawing:
    """Horizontal bar chart for Critical/High/Medium/Low counts."""
    bar_h    = 18
    bar_gap  = 10
    label_w  = 60
    num_w    = 30
    chart_w  = 300
    max_val  = max(counts.values()) or 1

    sevs    = ["Critical", "High", "Medium", "Low"]
    colours = [C_RED, C_ORANGE, C_YELLOW, C_GREEN]
    total_h = len(sevs) * (bar_h + bar_gap) + 10

    d = Drawing(label_w + chart_w + num_w + 20, total_h)

    for i, (sev, col) in enumerate(zip(sevs, colours)):
        y    = total_h - (i + 1) * (bar_h + bar_gap) + bar_gap
        val  = counts.get(sev, 0)
        bw   = int((val / max_val) * chart_w) if val > 0 else 2

        # Label
        d.add(String(0, y + 4, sev, fontName="Helvetica-Bold",
                     fontSize=9, fillColor=C_DARK))
        # Background track
        d.add(Rect(label_w, y, chart_w, bar_h,
                   fillColor=C_LIGHT_GRAY, strokeColor=None))
        # Value bar
        d.add(Rect(label_w, y, bw, bar_h,
                   fillColor=col, strokeColor=None))
        # Count
        d.add(String(label_w + chart_w + 6, y + 4, str(val),
                     fontName="Helvetica-Bold", fontSize=9,
                     fillColor=C_DARK))

    return d


# ── Main report builder ───────────────────────────────────────────────────
def generate_report(data: dict) -> bytes:
    """
    data keys expected:
        summary   — dict from /risk/summary
        assets    — list from /risk/assets
        findings  — list of dicts {asset, vulns[]}
        scan_date — ISO string or None
    """
    buf    = io.BytesIO()
    S      = _styles()
    doc    = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=20*mm, bottomMargin=18*mm,
        title="Security Vulnerability Assessment Report",
        author="VaultScan",
    )

    summary    = data.get("summary", {})
    assets     = data.get("assets", [])
    all_findings = data.get("findings", [])
    scan_date  = data.get("scan_date") or datetime.now().strftime("%d %B %Y")
    story      = []

    # ── PAGE 1: COVER ─────────────────────────────────────────────────────
    # Push content down (dark bg drawn by callback)
    story.append(Spacer(1, 52*mm))
    story.append(Paragraph("Security Vulnerability", S["cover_title"]))
    story.append(Paragraph("Assessment Report", S["cover_title"]))
    story.append(Spacer(1, 6*mm))
    story.append(Paragraph(
        "Automated analysis of infrastructure vulnerabilities, risk exposure,<br/>"
        "and CVE intelligence derived from Nessus scan data.",
        S["cover_sub"]
    ))
    story.append(Spacer(1, 10*mm))

    # Cover stat row
    total_assets = summary.get("total_assets", 0)
    total_vulns  = summary.get("total_vulns", 0)
    total_risk   = summary.get("total_risk", 0)
    cover_table  = Table(
        [[
            Paragraph(f"<b>{total_assets}</b><br/>Assets Scanned",   S["cover_meta"]),
            Paragraph(f"<b>{total_vulns}</b><br/>Vulnerabilities",    S["cover_meta"]),
            Paragraph(f"<b>{total_risk:.0f}</b><br/>Total Risk Score", S["cover_meta"]),
            Paragraph(f"<b>{summary.get('patch_available',0)}</b><br/>Patches Available", S["cover_meta"]),
        ]],
        colWidths=[(PAGE_W - 2*MARGIN) / 4] * 4,
    )
    cover_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#2e2a6e")),
        ("TEXTCOLOR",  (0,0), (-1,-1), C_WHITE),
        ("ROWPADDING", (0,0), (-1,-1), 10),
        ("BOX",        (0,0), (-1,-1), 0.5, colors.HexColor("#7c3aed")),
        ("INNERGRID",  (0,0), (-1,-1), 0.5, colors.HexColor("#4c1d95")),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(cover_table)
    story.append(Spacer(1, 10*mm))
    story.append(Paragraph(f"Report Date: {scan_date}", S["cover_meta"]))
    story.append(Paragraph("Classification: CONFIDENTIAL", S["cover_meta"]))
    story.append(PageBreak())

    # ── PAGE 2: EXECUTIVE SUMMARY ─────────────────────────────────────────
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph("Executive Summary", S["section_title"]))
    story.append(HRFlowable(width="100%", thickness=1.5,
                            color=C_PURPLE, spaceAfter=6))

    # Count severities from assets' findings
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for af in all_findings:
        for fnd in af.get("findings", []):
            sev = (fnd.get("vulnerability") or {}).get("severity") or ""
            key = sev.capitalize()
            if key in sev_counts:
                sev_counts[key] += 1

    critical_c = sev_counts["Critical"]
    high_c     = sev_counts["High"]
    patch_c    = summary.get("patch_available", 0)
    avg_risk   = summary.get("avg_risk", 0)

    narrative = (
        f"This report presents the findings of an automated vulnerability assessment "
        f"conducted across <b>{total_assets} assets</b>. The scan identified "
        f"<b>{total_vulns} unique vulnerabilities</b> producing a combined risk score "
        f"of <b>{total_risk:.0f}</b> with an average per-asset exposure of "
        f"<b>{avg_risk:.1f}</b>."
        f"<br/><br/>"
        f"The assessment identified <b>{critical_c} Critical</b> and "
        f"<b>{high_c} High</b> severity findings that require immediate attention. "
        f"Of all vulnerabilities identified, <b>{patch_c} have vendor patches "
        f"available</b> and should be prioritised for immediate remediation."
        f"<br/><br/>"
        f"Risk scores are computed as the product of each vulnerability's CVSS base "
        f"score, a severity weight multiplier (Critical ×2.0, High ×1.5, Medium ×1.0, "
        f"Low ×0.5), and the asset's configured criticality factor. Higher scores "
        f"indicate greater business exposure."
    )
    story.append(Paragraph(narrative, S["body"]))
    story.append(Spacer(1, 5*mm))

    # Top 5 riskiest assets summary table
    story.append(Paragraph("Highest Risk Assets", S["subsection"]))
    top5 = sorted(assets, key=lambda a: a.get("risk_score", 0), reverse=True)[:5]

    top5_data = [[
        Paragraph("Rank",       S["table_header"]),
        Paragraph("Hostname",   S["table_header"]),
        Paragraph("IP Address", S["table_header"]),
        Paragraph("Findings",   S["table_header"]),
        Paragraph("Risk Score", S["table_header"]),
    ]]
    for i, a in enumerate(top5, 1):
        top5_data.append([
            Paragraph(f"#{i}", S["table_cell"]),
            Paragraph(str(a.get("hostname", "")), S["table_cell_mono"]),
            Paragraph(str(a.get("ip", "")),       S["table_cell_mono"]),
            Paragraph(str(a.get("finding_count", "")), S["table_cell"]),
            Paragraph(f"{a.get('risk_score', 0):.1f}", S["table_cell"]),
        ])

    col_w = (PAGE_W - 2*MARGIN)
    t5_table = Table(top5_data,
                     colWidths=[col_w*0.08, col_w*0.30,
                                col_w*0.22, col_w*0.18, col_w*0.22])
    t5_table.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,0), C_DARK),
        ("TEXTCOLOR",   (0,0), (-1,0), C_WHITE),
        ("BACKGROUND",  (0,1), (-1,1), C_PURPLE_LIGHT),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_WHITE, C_LIGHT_GRAY]),
        ("GRID",        (0,0), (-1,-1), 0.4, colors.HexColor("#d1d5db")),
        ("ROWPADDING",  (0,0), (-1,-1), 6),
        ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
        ("ALIGN",       (0,0), (0,-1), "CENTER"),
        ("ALIGN",       (3,0), (4,-1), "CENTER"),
    ]))
    story.append(t5_table)
    story.append(PageBreak())

    # ── PAGE 3: SEVERITY DISTRIBUTION ─────────────────────────────────────
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph("Severity Distribution", S["section_title"]))
    story.append(HRFlowable(width="100%", thickness=1.5,
                            color=C_PURPLE, spaceAfter=6))
    story.append(Paragraph(
        "The chart below shows the distribution of findings by severity level "
        "across all scanned assets.",
        S["body"]
    ))
    story.append(Spacer(1, 6*mm))
    story.append(_severity_chart(sev_counts))
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph(
        "Figure 1 — Vulnerability count by severity level", S["caption"]
    ))
    story.append(Spacer(1, 8*mm))

    # Severity summary table
    sev_data = [[
        Paragraph("Severity", S["table_header"]),
        Paragraph("Count",    S["table_header"]),
        Paragraph("% of Total", S["table_header"]),
        Paragraph("Action Required", S["table_header"]),
    ]]
    total_findings = sum(sev_counts.values()) or 1
    actions = {
        "Critical": "Immediate — patch within 24 hours",
        "High":     "Urgent — remediate within 7 days",
        "Medium":   "Planned — address within 30 days",
        "Low":      "Scheduled — include in next cycle",
    }
    sev_colours = {
        "Critical": (C_RED,    C_RED_LIGHT),
        "High":     (C_ORANGE, C_ORANGE_LIGHT),
        "Medium":   (C_YELLOW, C_YELLOW_LIGHT),
        "Low":      (C_GREEN,  C_GREEN_LIGHT),
    }
    for sev in ["Critical", "High", "Medium", "Low"]:
        cnt = sev_counts[sev]
        pct = cnt / total_findings * 100
        sev_data.append([
            Paragraph(sev, S["table_cell"]),
            Paragraph(str(cnt), S["table_cell"]),
            Paragraph(f"{pct:.1f}%", S["table_cell"]),
            Paragraph(actions[sev], S["table_cell"]),
        ])

    cw = PAGE_W - 2*MARGIN
    sev_table = Table(sev_data,
                      colWidths=[cw*0.15, cw*0.12, cw*0.15, cw*0.58])
    style_cmds = [
        ("BACKGROUND",  (0,0), (-1,0), C_DARK),
        ("TEXTCOLOR",   (0,0), (-1,0), C_WHITE),
        ("GRID",        (0,0), (-1,-1), 0.4, colors.HexColor("#d1d5db")),
        ("ROWPADDING",  (0,0), (-1,-1), 7),
        ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
        ("ALIGN",       (1,1), (2,-1), "CENTER"),
    ]
    for i, sev in enumerate(["Critical", "High", "Medium", "Low"], 1):
        fg, bg = sev_colours[sev]
        style_cmds.append(("BACKGROUND", (0,i), (0,i), bg))
        style_cmds.append(("TEXTCOLOR",  (0,i), (0,i), fg))
        style_cmds.append(("FONTNAME",   (0,i), (0,i), "Helvetica-Bold"))
    sev_table.setStyle(TableStyle(style_cmds))
    story.append(sev_table)
    story.append(PageBreak())

    # ── PAGE 4: FULL ASSET RISK RANKING ───────────────────────────────────
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph("Asset Risk Ranking", S["section_title"]))
    story.append(HRFlowable(width="100%", thickness=1.5,
                            color=C_PURPLE, spaceAfter=6))
    story.append(Paragraph(
        "Assets are ranked by composite risk score. Criticality reflects "
        "the asset's business importance (1.0 = standard, higher = more critical).",
        S["body"]
    ))
    story.append(Spacer(1, 4*mm))

    rank_data = [[
        Paragraph("Rank",        S["table_header"]),
        Paragraph("Hostname",    S["table_header"]),
        Paragraph("IP",          S["table_header"]),
        Paragraph("Criticality", S["table_header"]),
        Paragraph("Findings",    S["table_header"]),
        Paragraph("Risk Score",  S["table_header"]),
    ]]
    sorted_assets = sorted(assets,
                           key=lambda a: a.get("risk_score", 0), reverse=True)
    max_score = sorted_assets[0].get("risk_score", 1) if sorted_assets else 1

    for i, a in enumerate(sorted_assets, 1):
        score = a.get("risk_score", 0)
        if score >= max_score * 0.66:
            score_color = C_RED
        elif score >= max_score * 0.33:
            score_color = C_ORANGE
        else:
            score_color = C_YELLOW

        rank_data.append([
            Paragraph(f"#{i}", S["table_cell"]),
            Paragraph(str(a.get("hostname", "")), S["table_cell_mono"]),
            Paragraph(str(a.get("ip", "")),       S["table_cell_mono"]),
            Paragraph(f"{a.get('criticality_score', 1.0):.1f}", S["table_cell"]),
            Paragraph(str(a.get("finding_count", 0)), S["table_cell"]),
            Paragraph(
                f'<font color="{score_color.hexval()}">'
                f'<b>{score:.1f}</b></font>',
                S["table_cell"]
            ),
        ])

    cw = PAGE_W - 2*MARGIN
    rank_table = Table(rank_data,
                       colWidths=[cw*0.08, cw*0.28, cw*0.20,
                                  cw*0.14, cw*0.14, cw*0.16])
    rank_table.setStyle(TableStyle([
        ("BACKGROUND",     (0,0), (-1,0), C_DARK),
        ("TEXTCOLOR",      (0,0), (-1,0), C_WHITE),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_WHITE, C_LIGHT_GRAY]),
        ("GRID",           (0,0), (-1,-1), 0.4, colors.HexColor("#d1d5db")),
        ("ROWPADDING",     (0,0), (-1,-1), 6),
        ("VALIGN",         (0,0), (-1,-1), "MIDDLE"),
        ("ALIGN",          (0,0), (0,-1), "CENTER"),
        ("ALIGN",          (3,0), (5,-1), "CENTER"),
    ]))
    story.append(rank_table)
    story.append(PageBreak())

    # ── PAGE 5+: DETAILED FINDINGS ────────────────────────────────────────
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph("Detailed Findings", S["section_title"]))
    story.append(HRFlowable(width="100%", thickness=1.5,
                            color=C_PURPLE, spaceAfter=6))
    story.append(Paragraph(
        "The following section details every finding per asset, ordered by "
        "risk score. CVE links, CVSS scores, CWE classifications, and patch "
        "availability are included where NVD data has been retrieved.",
        S["body"]
    ))
    story.append(Spacer(1, 4*mm))

    # Sort asset findings by asset risk score
    sorted_findings = sorted(
        all_findings,
        key=lambda af: af.get("risk_score", 0),
        reverse=True
    )

    for af in sorted_findings:
        aname     = af.get("hostname") or af.get("ip") or "Unknown"
        aip       = af.get("ip", "")
        ascore    = af.get("risk_score", 0)
        flist     = af.get("findings", [])
        if not flist:
            continue

        # Asset header block
        asset_block = [
            [
                Paragraph(f"<b>{aname}</b>", S["subsection"]),
                Paragraph(
                    f"IP: {aip} &nbsp;&nbsp; Risk Score: <b>{ascore:.1f}</b> &nbsp;&nbsp; "
                    f"Findings: <b>{len(flist)}</b>",
                    S["body_small"]
                ),
            ]
        ]
        ab = Table(asset_block, colWidths=[PAGE_W - 2*MARGIN])
        ab.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), C_PURPLE_LIGHT),
            ("LEFTPADDING",(0,0), (-1,-1), 10),
            ("TOPPADDING", (0,0), (-1,-1), 6),
            ("BOTTOMPADDING",(0,0),(-1,-1), 6),
            ("BOX",        (0,0), (-1,-1), 0.8, C_PURPLE),
        ]))

        # Findings table for this asset
        f_data = [[
            Paragraph("Vulnerability",  S["table_header"]),
            Paragraph("CVE",            S["table_header"]),
            Paragraph("Severity",       S["table_header"]),
            Paragraph("CVSS",           S["table_header"]),
            Paragraph("CWE",            S["table_header"]),
            Paragraph("Patch",          S["table_header"]),
            Paragraph("Risk",           S["table_header"]),
        ]]

        for fnd in sorted(flist, key=lambda x: x.get("risk_score", 0), reverse=True):
            v       = fnd.get("vulnerability") or {}
            sev     = v.get("severity") or "Unknown"
            fg, bg  = _severity_color(sev)
            cve     = v.get("cve") or "—"
            cvss    = v.get("cvss_score") or 0
            cwe     = v.get("cwe") or "—"
            patch   = "Yes" if v.get("patch_available") else "No"
            risk    = fnd.get("risk_score", 0)
            name    = (v.get("name") or "")[:60] + ("…" if len(v.get("name","")) > 60 else "")

            f_data.append([
                Paragraph(name, S["table_cell"]),
                Paragraph(cve,  S["table_cell_mono"]),
                Paragraph(sev,  S["table_cell"]),
                Paragraph(f"{cvss:.1f}" if cvss else "—", S["table_cell"]),
                Paragraph(cwe,  S["table_cell_mono"]),
                Paragraph(patch, S["table_cell"]),
                Paragraph(f"{risk:.1f}", S["table_cell"]),
            ])

        cw = PAGE_W - 2*MARGIN
        ft = Table(f_data,
                   colWidths=[cw*0.30, cw*0.14, cw*0.10,
                               cw*0.07, cw*0.12, cw*0.08, cw*0.08])

        ft_style = [
            ("BACKGROUND",  (0,0), (-1,0), colors.HexColor("#374151")),
            ("TEXTCOLOR",   (0,0), (-1,0), C_WHITE),
            ("GRID",        (0,0), (-1,-1), 0.3, colors.HexColor("#e5e7eb")),
            ("ROWPADDING",  (0,0), (-1,-1), 5),
            ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
            ("ALIGN",       (3,0), (6,-1), "CENTER"),
        ]
        # Colour severity column per row
        for ri, fnd in enumerate(flist, 1):
            v   = fnd.get("vulnerability") or {}
            sev = v.get("severity") or ""
            fg, bg = _severity_color(sev)
            ft_style.append(("BACKGROUND", (2,ri), (2,ri), bg))
            ft_style.append(("TEXTCOLOR",  (2,ri), (2,ri), fg))
            ft_style.append(("FONTNAME",   (2,ri), (2,ri), "Helvetica-Bold"))
            # Alternating row bg
            row_bg = C_WHITE if ri % 2 == 0 else C_LIGHT_GRAY
            for col in [0,1,3,4,5,6]:
                ft_style.append(("BACKGROUND", (col,ri), (col,ri), row_bg))

        ft.setStyle(TableStyle(ft_style))

        story.append(KeepTogether([ab, Spacer(1, 1*mm), ft, Spacer(1, 5*mm)]))

    story.append(PageBreak())

    # ── PAGE LAST: RECOMMENDATIONS ────────────────────────────────────────
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph("Recommendations", S["section_title"]))
    story.append(HRFlowable(width="100%", thickness=1.5,
                            color=C_PURPLE, spaceAfter=6))

    recs = _build_recommendations(sev_counts, summary, sorted_assets)
    for priority, title, body in recs:
        fg, bg = {
            "CRITICAL": (C_RED,    C_RED_LIGHT),
            "HIGH":     (C_ORANGE, C_ORANGE_LIGHT),
            "MEDIUM":   (C_YELLOW, C_YELLOW_LIGHT),
            "INFO":     (C_PURPLE, C_PURPLE_LIGHT),
        }.get(priority, (C_GRAY, C_LIGHT_GRAY))

        rec_block = Table(
            [[
                Paragraph(priority, ParagraphStyle(
                    "pri", fontSize=7, fontName="Helvetica-Bold",
                    textColor=fg, alignment=TA_CENTER
                )),
                [
                    Paragraph(title, ParagraphStyle(
                        "rec_title", fontSize=10, fontName="Helvetica-Bold",
                        textColor=C_DARK, spaceBefore=0
                    )),
                    Paragraph(body, S["body"]),
                ],
            ]],
            colWidths=[16*mm, PAGE_W - 2*MARGIN - 18*mm],
        )
        rec_block.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (0,0), bg),
            ("BACKGROUND",    (1,0), (1,0), C_WHITE),
            ("BOX",           (0,0), (-1,-1), 0.5, fg),
            ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING",    (0,0), (-1,-1), 8),
            ("BOTTOMPADDING", (0,0), (-1,-1), 8),
            ("LEFTPADDING",   (1,0), (1,0), 10),
        ]))
        story.append(rec_block)
        story.append(Spacer(1, 3*mm))

    # Build
    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return buf.getvalue()


def _build_recommendations(sev_counts, summary, sorted_assets):
    recs = []

    if sev_counts.get("Critical", 0) > 0:
        recs.append((
            "CRITICAL",
            f"Immediate Patch Deployment — {sev_counts['Critical']} Critical Findings",
            f"There are {sev_counts['Critical']} critical severity vulnerabilities across the "
            f"scanned infrastructure. These should be patched within 24 hours. Focus on assets "
            f"with the highest risk scores first and validate patches in a staging environment "
            f"where possible before production deployment."
        ))

    if sev_counts.get("High", 0) > 0:
        recs.append((
            "HIGH",
            f"Urgent Remediation Plan — {sev_counts['High']} High Severity Findings",
            f"{sev_counts['High']} high severity vulnerabilities require remediation within 7 days. "
            f"Coordinate with asset owners to schedule maintenance windows and prioritise assets "
            f"with criticality scores above 2.0."
        ))

    patch_c = summary.get("patch_available", 0)
    if patch_c > 0:
        recs.append((
            "HIGH",
            f"Apply Available Vendor Patches — {patch_c} Patches Ready",
            f"NVD data confirms that {patch_c} vulnerabilities have vendor patches available. "
            f"These represent the lowest-effort, highest-impact remediation actions. Patch "
            f"deployment should be prioritised over workaround implementation where possible."
        ))

    if sorted_assets:
        top = sorted_assets[0]
        recs.append((
            "MEDIUM",
            f"Review Criticality Scores — Highest Risk Asset: {top.get('hostname')}",
            f"The asset '{top.get('hostname')}' ({top.get('ip')}) carries the highest risk "
            f"score of {top.get('risk_score', 0):.1f}. Verify its criticality score reflects "
            f"its actual business importance. If this is a production system, consider network "
            f"segmentation or compensating controls while patches are applied."
        ))

    recs.append((
        "MEDIUM",
        "Establish Recurring Scan Cadence",
        "Vulnerability exposure changes as new CVEs are published and infrastructure evolves. "
        "Schedule automated Nessus scans weekly for internet-facing assets and monthly for "
        "internal infrastructure. Configure alerting for any new Critical findings."
    ))

    recs.append((
        "INFO",
        "Enrich Assets with Accurate Criticality Scores",
        "Risk scores multiply the asset criticality factor. Assets with default criticality "
        "(1.0) may be underweighted if they host sensitive data or critical services. Update "
        "criticality scores in VaultScan to reflect business context and ensure risk rankings "
        "reflect actual organisational exposure."
    ))

    return recs