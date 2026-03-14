from sqlalchemy.orm import Session
from app.models.asset import Asset


def create_asset(db: Session, hostname: str, ip_address: str, criticality: float = 1.0):
    asset = Asset(
        hostname=hostname,
        ip_address=ip_address,
        criticality_score=criticality
    )

    db.add(asset)
    db.commit()
    db.refresh(asset)

    return asset


def get_assets(db: Session):
    return db.query(Asset).all()