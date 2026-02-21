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

async def lookup_patient_by_id(patient_id: str) -> Optional[dict]:
    """
    Fetch patient record from the database by patient_id.
    Returns a dict with at least 'id' and 'primary_physician_id', or None if not found.
    Replace this stub with a real database query (e.g. via SQLAlchemy or asyncpg).
    """
    # TODO: replace with actual DB lookup, e.g.:
    #   return await db.fetch_one("SELECT * FROM patients WHERE id = :id AND deactivated_at IS NULL", {"id": patient_id})
    raise NotImplementedError("lookup_patient_by_id must be connected to the database layer")

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
    """
    Clinical staff access to patient PHI. Generates audit log entry.
    Ownership rules:
      - admin/nurse: may access any patient record.
      - doctor: may only access patients for whom they are the primary_physician_id.
    Returns 404 if the patient does not exist (avoids leaking record existence
    to unauthorised callers who receive 403 after the existence check).
    """
    # Fetch the patient record first — use a generic 404 so callers cannot
    # enumerate patient IDs via timing differences between 403 and 404.
    patient = await lookup_patient_by_id(patient_id)
    if patient is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Patient not found"
        )

    # Enforce doctor–patient relationship: doctors may only view their own patients.
    if current_user.role == "doctor":
        if patient.get("primary_physician_id") != current_user.user_id:
            # Return 403 after confirming existence to prevent IDOR enumeration
            # while still being explicit about the authorization failure to the
            # caller (who is already authenticated as clinical staff).
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: patient is not assigned to you"
            )

    # Audit logging is handled by AuditLogMiddleware for all /patients routes.
    return patient

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
