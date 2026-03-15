"""
risk_routes.py
~~~~~~~~~~~~~~
Endpoints:
  GET /risk/assets          — all assets ranked by risk_score desc
  GET /risk/assets/{id}     — single asset with its scored findings + vuln detail
  GET /risk/summary         — aggregated numbers for the risk dashboard
  POST /risk/recalculate    — force a full recalculation pass
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, joinedload

from app.database import get_db
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.vulnerability import Vulnerability

router = APIRouter(prefix="/risk", tags=["Risk"])


@router.get("/assets")
def ranked_assets(db: Session = Depends(get_db)):
    """
    Returns all assets sorted by risk_score descending.
    Frontend uses this for the exposure ranking table.
    """
    assets = (
        db.query(Asset)
        .order_by(Asset.risk_score.desc())
        .all()
    )
    return [
        {
            "id":                a.id,
            "hostname":          a.hostname,
            "ip":                a.ip,
            "criticality_score": a.criticality_score,
            "risk_score":        round(a.risk_score or 0.0, 2),
            "finding_count":     len(a.findings),
        }
        for a in assets
    ]


@router.get("/assets/{asset_id}")
def asset_risk_detail(asset_id: int, db: Session = Depends(get_db)):
    """
    Full risk breakdown for a single asset:
    each finding with its vulnerability's CVE, CVSS, CWE, patch status.
    """
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    findings = (
        db.query(Finding)
        .options(joinedload(Finding.vulnerability))
        .filter(Finding.asset_id == asset_id)
        .order_by(Finding.risk_score.desc())
        .all()
    )

    return {
        "id":                asset.id,
        "hostname":          asset.hostname,
        "ip":                asset.ip,
        "criticality_score": asset.criticality_score,
        "risk_score":        round(asset.risk_score or 0.0, 2),
        "findings": [
            {
                "finding_id":       f.id,
                "port":             f.port,
                "risk_score":       round(f.risk_score or 0.0, 2),
                "vulnerability": {
                    "id":               f.vulnerability.id,
                    "name":             f.vulnerability.name,
                    "severity":         f.vulnerability.severity,
                    "cve":              f.vulnerability.cve,
                    "cvss_score":       f.vulnerability.cvss_score,
                    "cwe":              f.vulnerability.cwe,
                    "description":      f.vulnerability.nvd_description or f.vulnerability.description,
                    "patch_available":  f.vulnerability.patch_available,
                    "nvd_fetched":      f.vulnerability.nvd_fetched,
                },
            }
            for f in findings
        ],
    }


@router.get("/summary")
def risk_summary(db: Session = Depends(get_db)):
    """
    High-level numbers for the risk overview cards.
    """
    assets = db.query(Asset).all()
    vulns  = db.query(Vulnerability).all()

    total_risk    = sum(a.risk_score or 0.0 for a in assets)
    avg_risk      = total_risk / len(assets) if assets else 0.0
    patched       = sum(1 for v in vulns if v.patch_available)
    nvd_enriched  = sum(1 for v in vulns if v.nvd_fetched)
    with_cve      = sum(1 for v in vulns if v.cve)

    # Top 5 riskiest assets
    top5 = sorted(assets, key=lambda a: a.risk_score or 0.0, reverse=True)[:5]

    return {
        "total_assets":    len(assets),
        "total_vulns":     len(vulns),
        "total_risk":      round(total_risk, 2),
        "avg_risk":        round(avg_risk, 2),
        "patch_available": patched,
        "nvd_enriched":    nvd_enriched,
        "with_cve":        with_cve,
        "top5_assets": [
            {
                "id":         a.id,
                "hostname":   a.hostname,
                "ip":         a.ip,
                "risk_score": round(a.risk_score or 0.0, 2),
            }
            for a in top5
        ],
    }


@router.post("/recalculate")
def force_recalculate(db: Session = Depends(get_db)):
    """
    Manually trigger a full risk recalculation.
    Useful after manually changing an asset's criticality_score via API.
    """
    from app.services.risk_engine import recalculate_all
    recalculate_all(db)
    return {"message": "Risk scores recalculated successfully"}


@router.patch("/assets/{asset_id}/criticality")
def update_criticality(
    asset_id: int,
    criticality: float,
    db: Session = Depends(get_db)
):
    """
    Update an asset's criticality score and immediately recalculate its risk.
    Valid range: 0.1 – 5.0
    """
    if not (0.1 <= criticality <= 5.0):
        raise HTTPException(status_code=400, detail="Criticality must be between 0.1 and 5.0")

    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    asset.criticality_score = criticality
    db.commit()

    from app.services.risk_engine import recalculate_asset_scores
    recalculate_asset_scores(db, [asset_id])

    return {"id": asset_id, "criticality_score": criticality, "risk_score": asset.risk_score}