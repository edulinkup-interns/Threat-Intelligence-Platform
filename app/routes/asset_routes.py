from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.crud.asset import create_asset, get_assets

router = APIRouter(prefix="/api")


@router.post("/assets")
def add_asset(
    hostname: str,
    ip_address: str,
    criticality: float = 1.0,
    db: Session = Depends(get_db)
):
    return create_asset(db, hostname, ip_address, criticality)


@router.get("/assets")
def list_assets(db: Session = Depends(get_db)):
    return get_assets(db)