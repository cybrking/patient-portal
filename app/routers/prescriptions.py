from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional, List
from datetime import date, datetime
from app.routers.auth import get_current_user, TokenData
from app.routers.patients import require_role
import hashlib
import hmac
import httpx
import os

router = APIRouter()

# External pharmacy network API
PHARMACY_API_URL = os.getenv("PHARMACY_API_URL")
PHARMACY_API_KEY = os.getenv("PHARMACY_API_KEY")

# DEA EPCS (Electronic Prescribing for Controlled Substances) endpoint
EPCS_ENDPOINT = os.getenv("EPCS_ENDPOINT")

# Secret used to derive an anonymous interaction-check token from patient_id.
# Must be set in the environment; never logged or transmitted externally.
_INTERACTION_TOKEN_SECRET = os.getenv("INTERACTION_TOKEN_SECRET", "")


def _anonymous_interaction_token(patient_id: str) -> str:
    """Return an HMAC-SHA256 pseudonym for patient_id.

    The token is a keyed hash — it is deterministic (the same patient always
    gets the same token within this installation) but cannot be reversed to
    recover patient_id without the secret key.  It contains no PHI and is
    safe to send to third-party APIs.
    """
    return hmac.new(
        _INTERACTION_TOKEN_SECRET.encode(),
        patient_id.encode(),
        hashlib.sha256,
    ).hexdigest()


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
    # Check drug interactions — patient_id is NOT forwarded to the third party.
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
    current_user: TokenData = Depends(require_role("doctor", "admin"))
):
    """
    Electronically transmit prescription to pharmacy via SureScripts network.
    Restricted to doctors and admins — patients must not be able to trigger
    pharmacy transmission (DEA regulatory requirement, drug diversion prevention).
    """
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
    """Check new drug against patient's current medication list via DrugBank API.

    patient_id is converted to an anonymous HMAC pseudonym before being sent
    to DrugBank so that no PHI leaves this system.
    """
    interaction_token = _anonymous_interaction_token(patient_id)
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://api.drugbank.com/v1/interactions",
            params={"interaction_token": interaction_token, "ndc": ndc_code},
            headers={"Authorization": f"Bearer {os.getenv('DRUGBANK_API_KEY')}"}
        )
        return response.json()

async def create_controlled_substance_rx(rx: PrescriptionCreate, user: TokenData):
    """Route through DEA EPCS for Schedule II-V substances."""
    pass

async def create_standard_rx(rx: PrescriptionCreate, user: TokenData):
    pass
