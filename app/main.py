from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import Base, engine
from app.models import *

from app.routes.asset_routes import router as asset_router
from app.routes.scan_routes import router as scan_router
from app.routes.scan_history_routes import router as scan_history_router
from app.routes.vulnerability_routes import router as vulnerability_router
from app.routes.finding_routes import router as finding_router

app = FastAPI()

# ---- CORS FIX ----
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create tables
Base.metadata.create_all(bind=engine)

# Register routes
app.include_router(asset_router)
app.include_router(scan_router)
app.include_router(scan_history_router)
app.include_router(vulnerability_router)
app.include_router(finding_router)