"""
report_routes.py
~~~~~~~~~~~~~~~~
GET /report/pdf  — generates and streams the full security report as a PDF
"""

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session, joinedload
from datetime import datetime
import io

from app.database import get_db
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.vulnerability import Vulnerability

router = APIRouter(prefix="/report", tags=["Report"])


@router.get("/pdf")
def generate_pdf_report(db: Session = Depends(get_db)):
    """
    Aggregates all data from the DB, generates a multi-page PDF report,
    and streams it back as an attachment.
    """
    from app.services.report_generator import generate_report

    # ── Summary ────────────────────────────────────────────────────────
    assets = db.query(Asset).all()
    vulns  = db.query(Vulnerability).all()

    total_risk   = sum(a.risk_score or 0.0 for a in assets)
    avg_risk     = total_risk / len(assets) if assets else 0.0
    patch_count  = sum(1 for v in vulns if v.patch_available)
    nvd_enriched = sum(1 for v in vulns if v.nvd_fetched)

    summary = {
        "total_assets":    len(assets),
        "total_vulns":     len(vulns),
        "total_risk":      round(total_risk, 2),
        "avg_risk":        round(avg_risk, 2),
        "patch_available": patch_count,
        "nvd_enriched":    nvd_enriched,
    }

    # ── Ranked assets ──────────────────────────────────────────────────
    sorted_assets = sorted(assets,
                           key=lambda a: a.risk_score or 0.0, reverse=True)
    assets_payload = [
        {
            "id":                a.id,
            "hostname":          a.hostname,
            "ip":                a.ip,
            "criticality_score": a.criticality_score,
            "risk_score":        round(a.risk_score or 0.0, 2),
            "finding_count":     len(a.findings),
        }
        for a in sorted_assets
    ]

    # ── Per-asset findings with vuln detail ────────────────────────────
    findings_payload = []
    for asset in sorted_assets:
        findings = (
            db.query(Finding)
            .options(joinedload(Finding.vulnerability))
            .filter(Finding.asset_id == asset.id)
            .order_by(Finding.risk_score.desc())
            .all()
        )
        if not findings:
            continue

        findings_payload.append({
            "hostname":   asset.hostname,
            "ip":         asset.ip,
            "risk_score": round(asset.risk_score or 0.0, 2),
            "findings": [
                {
                    "finding_id": f.id,
                    "port":       f.port,
                    "risk_score": round(f.risk_score or 0.0, 2),
                    "vulnerability": {
                        "name":            f.vulnerability.name,
                        "severity":        f.vulnerability.severity,
                        "cve":             f.vulnerability.cve,
                        "cvss_score":      f.vulnerability.cvss_score or 0.0,
                        "cwe":             f.vulnerability.cwe,
                        "description":     (
                            f.vulnerability.nvd_description
                            or f.vulnerability.description
                            or ""
                        ),
                        "patch_available": f.vulnerability.patch_available,
                        "nvd_fetched":     f.vulnerability.nvd_fetched,
                    },
                }
                for f in findings
            ],
        })

    # ── Generate PDF ───────────────────────────────────────────────────
    pdf_bytes = generate_report({
        "summary":   summary,
        "assets":    assets_payload,
        "findings":  findings_payload,
        "scan_date": datetime.now().strftime("%d %B %Y"),
    })

    filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Content-Length": str(len(pdf_bytes)),
        }
    )