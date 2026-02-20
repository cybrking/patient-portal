from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import date
from app.routers.auth import get_current_user, TokenData

router = APIRouter()

class PatientBase(BaseModel):
    first_name: str
    last_name: str
    date_of_birth: date
    email: EmailStr
    phone: str
    ssn_last4: str  # PHI — stored encrypted
    insurance_id: str
    insurance_provider: str

class PatientCreate(PatientBase):
    emergency_contact_name: str
    emergency_contact_phone: str

class PatientResponse(PatientBase):
    id: str
    mrn: str  # Medical Record Number
    created_at: str
    primary_physician_id: Optional[str]

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
