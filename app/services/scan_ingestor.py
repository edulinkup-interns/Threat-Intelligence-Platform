from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.models.finding import Finding


def ingest_scan(db: Session, findings):

    stored = 0

    for item in findings:

        # find or create asset
        asset = db.query(Asset).filter(
            Asset.ip_address == item["host"]
        ).first()

        if not asset:
            asset = Asset(
                hostname=item["host"],
                ip_address=item["host"],
                criticality_score=1.0
            )
            db.add(asset)
            db.commit()
            db.refresh(asset)

        # find or create vulnerability
        vuln = db.query(Vulnerability).filter(
            Vulnerability.cve == item["cve"]
        ).first()

        if not vuln:
            vuln = Vulnerability(
                cve=item["cve"],
                title=item["name"],
                description=item["description"],
                cvss_score=item["cvss"],
                severity=item["severity"]
            )
            db.add(vuln)
            db.commit()
            db.refresh(vuln)

        # create finding
        finding = Finding(
            asset_id=asset.id,
            vulnerability_id=vuln.id,
            port=item["port"],
            service="unknown",
            risk_score=item["cvss"]
        )

        db.add(finding)
        stored += 1

    db.commit()

    return stored