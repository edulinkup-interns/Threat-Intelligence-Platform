from sqlalchemy import Column, Integer, DateTime
from datetime import datetime
from app.database import Base

class Scan(Base):

    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)

    assets = Column(Integer)
    vulnerabilities = Column(Integer)
    findings = Column(Integer)

    created_at = Column(DateTime, default=datetime.utcnow)