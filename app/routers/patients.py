from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, EmailStr, field_validator, model_validator
from typing import Optional, List
from datetime import date
from app.routers.auth import get_current_user, TokenData
from app.crypto import encrypt_phi, decrypt_phi
import re

router = APIRouter()

_SSN_LAST4_RE = re.compile(r"^\d{4}$")


class PatientBase(BaseModel):
    first_name: str
    last_name: str
    date_of_birth: date
    email: EmailStr
    phone: str
    ssn_last4: str  # PHI — stored encrypted; plaintext only in memory
    insurance_id: str
    insurance_provider: str


class PatientCreate(PatientBase):
    emergency_contact_name: str
    emergency_contact_phone: str

    @field_validator("ssn_last4")
    @classmethod
    def validate_and_encrypt_ssn(cls, v: str) -> str:
        """Validate format then encrypt before the value leaves this model."""
        if not _SSN_LAST4_RE.match(v):
            raise ValueError("ssn_last4 must be exactly 4 digits")
        return encrypt_phi(v)


class PatientResponse(PatientBase):
    id: str
    mrn: str  # Medical Record Number
    created_at: str
    primary_physician_id: Optional[str]

    @field_validator("ssn_last4")
    @classmethod
    def decrypt_ssn(cls, v: str) -> str:
        """Decrypt the stored ciphertext before returning it to the caller."""
        # If the value is already plaintext 4-digits (e.g. in tests), pass through.
        if _SSN_LAST4_RE.match(v):
            return v
        return decrypt_phi(v)


class PatientUpdate(BaseModel):
    phone: Optional[str]
    email: Optional[str]
    insurance_id: Optional[str]
    insurance_provider: Optional[str]
    emergency_contact_name: Optional[str]
    emergency_contact_phone: Optional[str]


def require_role(*roles):
    def role_checker(current_user: TokenData = Depends(get_current_user)):
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role: {roles}"
            )
        return current_user
    return role_checker


@router.get("/me", response_model=PatientResponse)
async def get_my_profile(current_user: TokenData = Depends(get_current_user)):
    """Patient views their own PHI."""
    pass


@router.put("/me", response_model=PatientResponse)
async def update_my_profile(
    update: PatientUpdate,
    current_user: TokenData = Depends(get_current_user)
):
    """Patient updates their own contact/insurance info."""
    pass


@router.get("/{patient_id}", response_model=PatientResponse)
async def get_patient(
    patient_id: str,
    current_user: TokenData = Depends(require_role("doctor", "nurse", "admin"))
):
    """Clinical staff access to patient PHI. Generates audit log entry."""
    # Enforce: doctors can only view patients assigned to them
    pass


@router.get("/", response_model=List[PatientResponse])
async def search_patients(
    name: Optional[str] = Query(None),
    mrn: Optional[str] = Query(None),
    dob: Optional[date] = Query(None),
    current_user: TokenData = Depends(require_role("doctor", "nurse", "admin"))
):
    """Search patients — PHI search requires clinical role."""
    pass


@router.post("/", response_model=PatientResponse, status_code=201)
async def register_patient(
    patient: PatientCreate,
    current_user: TokenData = Depends(require_role("admin", "nurse"))
):
    """Register a new patient. Assigns MRN. Sends welcome email."""
    pass


@router.delete("/{patient_id}")
async def deactivate_patient(
    patient_id: str,
    current_user: TokenData = Depends(require_role("admin"))
):
    """Soft delete — HIPAA requires 6-year retention, no hard deletes."""
    pass


@router.get("/{patient_id}/consent")
async def get_consent_records(
    patient_id: str,
    current_user: TokenData = Depends(require_role("doctor", "admin"))
):
    """View signed consent forms and data sharing agreements."""
    pass


@router.post("/{patient_id}/consent")
async def record_consent(
    patient_id: str,
    consent_type: str,
    current_user: TokenData = Depends(require_role("admin", "nurse"))
):
    """Record new consent (treatment, data sharing, research)."""
    pass
