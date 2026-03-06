from fastapi import APIRouter, UploadFile, File, Depends
from sqlalchemy.orm import Session
import shutil
import os

from app.database import get_db
from app.services.parser import parse_nessus_csv
from app.services.scan_ingestor import ingest_scan

router = APIRouter(prefix="/scan")


@router.post("/upload")
async def upload_scan(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):

    # ensure upload folder exists
    upload_dir = "uploads"
    os.makedirs(upload_dir, exist_ok=True)

    file_path = f"{upload_dir}/{file.filename}"

    # save uploaded file
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # parse CSV
    findings = parse_nessus_csv(file_path)

    # ingest into database
    stored = ingest_scan(db, findings)

    return {
        "parsed_findings": len(findings),
        "stored_findings": stored
    }