"""
scan_ingestor.py
~~~~~~~~~~~~~~~~
Ingests parsed Nessus findings, then:
  1. Calls recalculate_all() synchronously (fast — no network)
  2. Launches NVD enrichment in a background thread, then calls
     recalculate_all() again so updated CVSS scores feed into risk
"""

import logging
import threading

logger = logging.getLogger(__name__)


def ingest_scan(db, findings: list[dict]) -> dict:
    from app.models.asset import Asset
    from app.models.vulnerability import Vulnerability
    from app.models.finding import Finding

    asset_count   = 0
    vuln_count    = 0
    finding_count = 0
    new_vuln_ids  = []

    for f in findings:

        # ── ASSET ─────────────────────────────────────────────────────────
        asset = db.query(Asset).filter(Asset.ip == str(f["host"])).first()
        if not asset:
            asset = Asset(hostname=str(f["host"]), ip=str(f["host"]))
            db.add(asset)
            db.flush()          # gives asset.id without committing
            asset_count += 1

        # ── VULNERABILITY ──────────────────────────────────────────────────
        vuln = db.query(Vulnerability).filter(
            Vulnerability.name == f["name"]
        ).first()

        if not vuln:
            try:
                cvss = float(f.get("cvss") or 0.0)
            except (ValueError, TypeError):
                cvss = 0.0

            raw_cve = str(f.get("cve") or "").strip()
            # Nessus sometimes lists multiple CVEs comma-separated — take first
            primary_cve = raw_cve.split(",")[0].strip() or None

            vuln = Vulnerability(
                name        = f["name"],
                severity    = f.get("severity") or "",
                description = f.get("description") or "",
                cve         = primary_cve,
                cvss_score  = cvss,
            )
            db.add(vuln)
            db.flush()
            new_vuln_ids.append(vuln.id)
            vuln_count += 1

        # ── FINDING ────────────────────────────────────────────────────────
        finding = Finding(
            asset_id         = asset.id,
            vulnerability_id = vuln.id,
            port             = str(f.get("port") or "0"),
            service          = str(f.get("service") or ""),
            risk_score       = 0.0,   # will be set by recalculate_all below
        )
        db.add(finding)
        finding_count += 1

    # Single commit for all rows
    db.commit()
    logger.info("Ingested %d assets, %d vulns, %d findings",
                asset_count, vuln_count, finding_count)

    # ── RISK SCORING — synchronous, runs immediately after commit ─────────
    # recalculate_all() loads fresh from DB so there are zero stale-cache
    # issues — it sees exactly what was just committed.
    from app.services.risk_engine import recalculate_all
    recalculate_all(db)

    # ── NVD ENRICHMENT — background thread so response returns fast ───────
    if new_vuln_ids:
        _launch_nvd_thread(new_vuln_ids)

    return {
        "assets":          asset_count,
        "vulnerabilities": vuln_count,
        "findings":        finding_count,
    }


def _launch_nvd_thread(vuln_ids: list[int]) -> None:
    """
    Fetches NVD data for new vulns, then runs a second recalculate_all()
    pass so updated CVSS scores from NVD feed into risk scores.
    Uses its own DB session — never touches the request session.
    """
    def _run():
        from app.database import SessionLocal
        from app.services.nvd_client import enrich_vulnerabilities
        from app.services.risk_engine import recalculate_all

        db = SessionLocal()
        try:
            logger.info("NVD thread: enriching %d vulns", len(vuln_ids))
            enrich_vulnerabilities(db, vuln_ids)

            # Second scoring pass now that CVSS may have been updated by NVD
            logger.info("NVD thread: re-scoring after enrichment")
            recalculate_all(db)
        except Exception as e:
            logger.error("NVD/risk background thread failed: %s", e)
        finally:
            db.close()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    logger.info("NVD enrichment thread launched for %d vulns", len(vuln_ids))