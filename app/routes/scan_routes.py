from fastapi import APIRouter, UploadFile, File, Depends, HTTPException
from sqlalchemy.orm import Session
import shutil
import os
import uuid

from app.database import get_db
from app.services.parser import parse_nessus_csv
from app.services.scan_ingestor import ingest_scan
from app.models.scan import Scan

router = APIRouter(prefix="/scan", tags=["Scans"])


@router.post("/upload")
async def upload_scan(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):

    try:

        # ensure uploads directory exists
        os.makedirs("uploads", exist_ok=True)

        # prevent filename collisions
        unique_name = f"{uuid.uuid4()}_{file.filename}"
        file_path = os.path.join("uploads", unique_name)

        # save uploaded file
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # parse scan file
        findings = parse_nessus_csv(file_path)

        if not findings:
            raise HTTPException(status_code=400, detail="Scan file contains no findings")

        # ingest scan data into DB
        stored = ingest_scan(db, findings)

        # record scan history
        scan = Scan(
            assets=stored["assets"],
            vulnerabilities=stored["vulnerabilities"],
            findings=stored["findings"]
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        return {
            "message": "Scan processed successfully",
            "assets": stored["assets"],
            "vulnerabilities": stored["vulnerabilities"],
            "findings": stored["findings"]
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))