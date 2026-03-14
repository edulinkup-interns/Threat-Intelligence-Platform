from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.scan import Scan

router = APIRouter(prefix="/scans")

@router.get("/")
def get_scans(db: Session = Depends(get_db)):

    scans = db.query(Scan).order_by(Scan.created_at.desc()).all()

    return scans