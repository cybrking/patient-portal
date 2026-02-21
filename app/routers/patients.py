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


async def check_physician_patient_assignment(physician_id: str, patient_id: str) -> bool:
    """
    Verify an active care relationship exists between the physician and patient.

    Replace the stub body below with a real database query, e.g.:
        result = await db.fetchval(
            "SELECT 1 FROM care_team "
            "WHERE patient_id = $1 AND physician_id = $2 AND is_active = TRUE "
            "UNION "
            "SELECT 1 FROM appointments "
            "WHERE patient_id = $1 AND physician_id = $2 "
            "  AND status IN ('scheduled','confirmed','completed') "
            "LIMIT 1",
            patient_id, physician_id
        )
        return result is not None
    """
    # TODO: replace with real DB query (see docstring above)
    raise NotImplementedError(
        "check_physician_patient_assignment must be implemented with a real DB query"
    )


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
    current_user: TokenData = Depends(require_role("doctor", "nurse", "admin",
                                                   "psychiatrist", "addiction_specialist"))
):
    """
    Clinical staff access to patient PHI. Generates audit log entry.
    Doctors, psychiatrists, and addiction_specialists may only access
    patients assigned to them via an active appointment or care_team entry.
    Nurses and admins have broader access (no assignment check required).
    """
    # Roles that must have an active patient assignment to proceed
    assignment_checked_roles = {"doctor", "psychiatrist", "addiction_specialist"}

    if current_user.role in assignment_checked_roles:
        try:
            assigned = await check_physician_patient_assignment(
                current_user.user_id, patient_id
            )
        except NotImplementedError:
            # Fail closed: deny access until the DB check is implemented
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: patient-physician assignment check not available"
            )
        if not assigned:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: no active care relationship with this patient"
            )

    # TODO: fetch and return patient record from DB
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
