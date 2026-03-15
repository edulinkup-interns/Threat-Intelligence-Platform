"""

  finding.risk_score  = cvss_score * severity_weight
  asset.risk_score    = sum(finding.risk_score) * criticality_score

Severity weights

  Critical → 2.0
  High     → 1.5
  Medium   → 1.0
  Low      → 0.5
  fallback → 0.1
"""

import logging
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

SEVERITY_WEIGHTS = {
    "critical": 2.0,
    "high":     1.5,
    "medium":   1.0,
    "low":      0.5,
}


def _weight(severity) -> float:
    if not severity:
        return 0.1
    return SEVERITY_WEIGHTS.get(severity.strip().lower(), 0.1)


def recalculate_all(db: Session) -> None:
    """
    Single-pass full recalculation.
    Loads all data up front into Python — avoids any lazy-load / stale-cache
    issues that come from calling db.get() after a flush/commit.
    This is the ONE function everything funnels through.
    """
    from app.models.finding import Finding
    from app.models.vulnerability import Vulnerability
    from app.models.asset import Asset

    logger.info("Risk recalculation started")

    # ── 1. Build vuln lookup: id → (cvss, severity) ──────────────────────
    vuln_map = {}
    for v in db.query(Vulnerability).all():
        vuln_map[v.id] = (
            float(v.cvss_score or 0.0),
            v.severity or "",
        )

    # ── 2. Score every finding and bucket by asset ────────────────────────
    asset_totals = {}   # asset_id → running sum of finding scores

    for f in db.query(Finding).all():
        cvss, sev = vuln_map.get(f.vulnerability_id, (0.0, ""))
        score = round(cvss * _weight(sev), 3)
        f.risk_score = score
        asset_totals[f.asset_id] = asset_totals.get(f.asset_id, 0.0) + score

    # ── 3. Roll up to assets ──────────────────────────────────────────────
    for a in db.query(Asset).all():
        total = asset_totals.get(a.id, 0.0)
        a.risk_score = round(total * float(a.criticality_score or 1.0), 3)

    db.commit()
    logger.info(
        "Risk recalculation done — %d assets, %d findings updated",
        len(asset_totals), sum(1 for _ in vuln_map)
    )