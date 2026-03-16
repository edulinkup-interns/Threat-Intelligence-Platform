from sqlalchemy import Column, Integer, String, Float
from sqlalchemy.orm import relationship
from app.database import Base


class Asset(Base):
    __tablename__ = "assets"

    id                = Column(Integer, primary_key=True, index=True)
    hostname          = Column(String, index=True)
    ip                = Column(String, index=True)

    
    criticality_score = Column(Float, default=1.0)

  
    risk_score        = Column(Float, default=0.0)

    findings = relationship("Finding", back_populates="asset")
