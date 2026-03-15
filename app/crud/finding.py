from sqlalchemy.orm import Session
from app.models.finding import Finding


def get_findings(db: Session):
    return db.query(Finding).all()