import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import Base, engine
from app.models import *  # noqa: F401,F403

from app.routes.asset_routes         import router as asset_router
from app.routes.scan_routes          import router as scan_router
from app.routes.scan_history_routes  import router as scan_history_router
from app.routes.vulnerability_routes import router as vulnerability_router
from app.routes.finding_routes       import router as finding_router
from app.routes.risk_routes          import router as risk_router
from app.routes.report_routes        import router as report_router

app = FastAPI(title="VaultScan API")

# FRONTEND_URL can be set as an environment variable on Railway
# so you don't have to hardcode your Vercel URL here
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        FRONTEND_URL,               # ← your Vercel URL goes in Railway env vars
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

Base.metadata.create_all(bind=engine)

app.include_router(asset_router)
app.include_router(scan_router)
app.include_router(scan_history_router)
app.include_router(vulnerability_router)
app.include_router(finding_router)
app.include_router(risk_router)
app.include_router(report_router)
