from sqlalchemy import Column, Integer, ForeignKey, String, Float
from sqlalchemy.orm import relationship
from app.database import Base


class Finding(Base):
    __tablename__ = "findings"

    id               = Column(Integer, primary_key=True, index=True)
    asset_id         = Column(Integer, ForeignKey("assets.id"))
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"))

    port             = Column(String)
    service          = Column(String)

    risk_score       = Column(Float, default=0.0)

    asset            = relationship("Asset",          back_populates="findings")
    vulnerability    = relationship("Vulnerability",  back_populates="findings")
