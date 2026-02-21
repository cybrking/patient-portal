from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from contextlib import asynccontextmanager
import logging
import os
import sys

from app.routers import patients, appointments, records, auth, admin, prescriptions
from app.middleware.audit import AuditLogMiddleware
from app.middleware.rate_limit import RateLimitMiddleware

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Required environment variables — fail fast at startup if any are missing.
# This prevents the application from starting in a partially-configured state
# that could silently skip security controls or send unauthenticated requests.
# ---------------------------------------------------------------------------
_REQUIRED_ENV_VARS = [
    "DRUGBANK_API_KEY",
    "PHARMACY_API_KEY",
    "TELEHEALTH_API_KEY",
    "INTERACTION_TOKEN_SECRET",
    "JWT_SECRET_KEY",
]


def _validate_required_env_vars() -> None:
    missing = [var for var in _REQUIRED_ENV_VARS if not os.getenv(var)]
    if missing:
        logger.critical(
            "Missing required environment variables: %s — refusing to start.",
            ", ".join(missing),
        )
        sys.exit(1)


@asynccontextmanager
async def lifespan(app: FastAPI):
    _validate_required_env_vars()
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
