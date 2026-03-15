from sqlalchemy import Column, Integer, String, Float
from sqlalchemy.orm import relationship
from app.database import Base


class Asset(Base):
    __tablename__ = "assets"

    id                = Column(Integer, primary_key=True, index=True)
    hostname          = Column(String, index=True)
    ip                = Column(String, index=True)

    # Set manually or via API; defaults to 1.0 (neutral)
    criticality_score = Column(Float, default=1.0)

    # Computed by risk_engine after every ingest
    # Formula: sum(cvss * severity_weight) * criticality_score
    risk_score        = Column(Float, default=0.0)

    findings = relationship("Finding", back_populates="asset")