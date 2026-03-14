from sqlalchemy import Column, Integer, String, Float
from sqlalchemy.orm import relationship
from app.database import Base


class Asset(Base):

    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)

    hostname = Column(String, index=True)
    ip = Column(String, index=True)

    # criticality_score used by create_asset in crud/asset.py
    criticality_score = Column(Float, default=1.0)

    # ✅ FIX: This was missing — Finding.asset uses back_populates="asset"
    # and Finding.asset_id is a FK to assets.id, so Asset MUST declare this
    findings = relationship("Finding", back_populates="asset")