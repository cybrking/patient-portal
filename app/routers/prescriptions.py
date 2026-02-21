from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Optional, List
from datetime import date, datetime
from app.routers.auth import get_current_user, TokenData
from app.routers.patients import require_role
import httpx
import os

router = APIRouter()

# External pharmacy network API
PHARMACY_API_URL = os.getenv("PHARMACY_API_URL")
PHARMACY_API_KEY = os.getenv("PHARMACY_API_KEY")

# DEA EPCS (Electronic Prescribing for Controlled Substances) endpoint
EPCS_ENDPOINT = os.getenv("EPCS_ENDPOINT")

class Prescription(BaseModel):
    id: str
    patient_id: str
    prescriber_id: str
    drug_name: str
    ndc_code: str          # National Drug Code
    dosage: str
    frequency: str
    quantity: int
    refills_remaining: int
    is_controlled: bool    # Schedule II-V — requires DEA EPCS
    dea_schedule: Optional[str]
    issued_date: date
    expiry_date: date
    pharmacy_id: Optional[str]
    status: str            # pending | sent | filled | cancelled

class PrescriptionCreate(BaseModel):
    patient_id: str
    drug_name: str
    ndc_code: str
    dosage: str
    frequency: str
    quantity: int
    refills: int
    is_controlled: bool = False
    dea_schedule: Optional[str] = None
    notes: Optional[str] = None

class PharmacyTransfer(BaseModel):
    prescription_id: str
    pharmacy_id: str
    pharmacy_ncpdp: str    # National Council for Prescription Drug Programs ID

async def get_prescription_from_db(prescription_id: str) -> dict:
    """
    Fetch prescription record from the database.
    Returns a dict with at least 'prescriber_id' and 'is_controlled'.
    Stub — real implementation queries PostgreSQL.
    """
    # TODO: replace with actual DB query
    raise NotImplementedError("get_prescription_from_db must be implemented")

def require_mfa_for_controlled(current_user: TokenData) -> TokenData:
    """
    Dependency that enforces MFA completion (mfa_verified claim in JWT)
    before allowing transmission of controlled substances.
    """
    if not getattr(current_user, "mfa_verified", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="DEA EPCS requires MFA verification. Please complete two-factor authentication."
        )
    return current_user

@router.get("/patient/{patient_id}", response_model=List[Prescription])
async def get_patient_prescriptions(
    patient_id: str,
    active_only: bool = True,
    current_user: TokenData = Depends(get_current_user)
):
    """View prescriptions. Patients see own only. Doctors see their patients."""
    pass

@router.post("/", response_model=Prescription)
async def create_prescription(
    rx: PrescriptionCreate,
    current_user: TokenData = Depends(require_role("doctor"))
):
    """
    Issue new prescription.
    Controlled substances routed through DEA EPCS with two-factor auth.
    Triggers drug interaction check via external API.
    """
    # Check drug interactions
    interactions = await check_drug_interactions(rx.patient_id, rx.ndc_code)
    if interactions.get("severe"):
        raise HTTPException(status_code=400, detail=f"Severe drug interaction: {interactions['detail']}")

    if rx.is_controlled:
        # EPCS requires identity proofing + hard token
        return await create_controlled_substance_rx(rx, current_user)

    return await create_standard_rx(rx, current_user)

@router.post("/{prescription_id}/send-to-pharmacy")
async def send_to_pharmacy(
    prescription_id: str,
    transfer: PharmacyTransfer,
    current_user: TokenData = Depends(require_role("doctor"))
):
    """
    Electronically transmit prescription to pharmacy via SureScripts network.
    Restricted to doctors only — patients and admins must not be able to trigger
    pharmacy transmission (DEA regulatory requirement, drug diversion prevention).

    Additional controls enforced:
    - Transmitting doctor must be the original prescriber.
    - Controlled substances require MFA (DEA EPCS two-factor) verified in the
      current session (mfa_verified JWT claim).
    """
    # Fetch the prescription to verify ownership and controlled status
    try:
        prescription = await get_prescription_from_db(prescription_id)
    except NotImplementedError:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Prescription lookup not yet implemented"
        )

    # Ownership check: only the original prescriber may transmit
    if prescription["prescriber_id"] != current_user.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the original prescriber may transmit this prescription to a pharmacy."
        )

    # DEA EPCS two-factor enforcement for controlled substances
    if prescription.get("is_controlled"):
        require_mfa_for_controlled(current_user)

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{PHARMACY_API_URL}/transmit",
            json={"prescription_id": prescription_id, "ncpdp": transfer.pharmacy_ncpdp},
            headers={"X-API-Key": PHARMACY_API_KEY},
            timeout=10.0
        )
        response.raise_for_status()
    return response.json()

@router.post("/{prescription_id}/refill")
async def request_refill(
    prescription_id: str,
    current_user: TokenData = Depends(get_current_user)
):
    """Patient requests refill — notifies prescribing physician for approval."""
    pass

@router.delete("/{prescription_id}")
async def cancel_prescription(
    prescription_id: str,
    reason: str,
    current_user: TokenData = Depends(require_role("doctor", "admin"))
):
    """Cancel prescription and notify pharmacy if already transmitted."""
    pass

async def check_drug_interactions(patient_id: str, ndc_code: str) -> dict:
    """Check new drug against patient's current medication list via DrugBank API."""
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"https://api.drugbank.com/v1/interactions",
            params={"patient_id": patient_id, "ndc": ndc_code},
            headers={"Authorization": f"Bearer {os.getenv('DRUGBANK_API_KEY')}"}
        )
        return response.json()

async def create_controlled_substance_rx(rx: PrescriptionCreate, user: TokenData):
    """Route through DEA EPCS for Schedule II-V substances."""
    pass

async def create_standard_rx(rx: PrescriptionCreate, user: TokenData):
    pass
