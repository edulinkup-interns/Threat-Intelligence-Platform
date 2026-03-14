from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.models.finding import Finding


def ingest_scan(db, findings):

    asset_count = 0
    vuln_count = 0
    finding_count = 0

    for f in findings:

        # -------- ASSET --------
        asset = db.query(Asset).filter(Asset.ip == f["host"]).first()

        if not asset:
            asset = Asset(
                hostname=f["host"],
                ip=f["host"]
            )
            db.add(asset)
            db.commit()
            db.refresh(asset)
            asset_count += 1

        # -------- VULNERABILITY --------
        vuln = db.query(Vulnerability).filter(
            Vulnerability.name == f["name"]
        ).first()

        if not vuln:
            vuln = Vulnerability(
                name=f["name"],
                severity=f["severity"],
                description=f.get("description", "")
            )
            db.add(vuln)
            db.commit()
            db.refresh(vuln)
            vuln_count += 1

        # -------- FINDING --------
        finding = Finding(
            asset_id=asset.id,
            vulnerability_id=vuln.id,
            port=f.get("port", "0")
        )

        db.add(finding)
        db.commit()

        finding_count += 1

    return {
        "assets": asset_count,
        "vulnerabilities": vuln_count,
        "findings": finding_count
    }