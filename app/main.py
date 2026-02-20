from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from contextlib import asynccontextmanager
import logging

from app.routers import patients, appointments, records, auth, admin, prescriptions
from app.middleware.audit import AuditLogMiddleware
from app.middleware.rate_limit import RateLimitMiddleware

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting patient portal service")
    yield
    logger.info("Shutting down patient portal service")

app = FastAPI(
    title="HealthBridge Patient Portal",
    description="HIPAA-compliant patient portal for managing appointments, medical records, and prescriptions",
    version="1.0.0",
    lifespan=lifespan
)

# CORS — allows frontend on separate domain
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://portal.healthbridge.io", "https://admin.healthbridge.io"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(AuditLogMiddleware)
app.add_middleware(RateLimitMiddleware, requests_per_minute=60)

# Routers
app.include_router(auth.router, prefix="/auth", tags=["Authentication"])
app.include_router(patients.router, prefix="/patients", tags=["Patients"])
app.include_router(appointments.router, prefix="/appointments", tags=["Appointments"])
app.include_router(records.router, prefix="/records", tags=["Medical Records"])
app.include_router(prescriptions.router, prefix="/prescriptions", tags=["Prescriptions"])
app.include_router(admin.router, prefix="/admin", tags=["Admin"])

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "patient-portal"}
