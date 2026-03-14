from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.crud.asset import create_asset, get_assets

# ✅ FIX: Changed prefix from "/api" to "/assets" to be consistent with
# all other routers (/vulnerabilities, /findings, /scans, /scan).
# Previously assets lived at /api/assets while everything else was at root level.
router = APIRouter(prefix="/assets", tags=["Assets"])


@router.post("/")
def add_asset(
    hostname: str,
    ip_address: str,
    criticality: float = 1.0,
    db: Session = Depends(get_db)
):
    return create_asset(db, hostname, ip_address, criticality)


@router.get("/")
def list_assets(db: Session = Depends(get_db)):
    return get_assets(db)