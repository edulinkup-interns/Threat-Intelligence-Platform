from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.crud.finding import get_findings

router = APIRouter(prefix="/findings")


@router.get("/")
def list_findings(db: Session = Depends(get_db)):
    return get_findings(db)