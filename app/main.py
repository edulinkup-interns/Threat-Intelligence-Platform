from fastapi import FastAPI
from app.database import Base, engine

# Import models so SQLAlchemy registers them
import app.models.asset
import app.models.vulnerability
import app.models.finding
import app.models.user

# Import routers
from app.routes.asset_routes import router as asset_router
from app.routes.scan_routes import router as scan_router

app = FastAPI()

# Create database tables
Base.metadata.create_all(bind=engine)

# Register routers
app.include_router(asset_router)
app.include_router(scan_router)

@app.get("/")
def root():
    return {"message": "Security Report Engine Running"}