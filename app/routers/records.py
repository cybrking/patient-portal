from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, BackgroundTasks, status
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
from app.routers.auth import get_current_user, TokenData
from app.routers.patients import require_role
import boto3
import os

router = APIRouter()

S3_BUCKET = os.getenv("S3_RECORDS_BUCKET")
S3_KMS_KEY = os.getenv("S3_KMS_KEY_ARN")  # Server-side encryption key

# Roles permitted to access sensitive (42 CFR Part 2) records
SENSITIVE_RECORD_ROLES = {"psychiatrist", "addiction_specialist"}

s3 = boto3.client(
    "s3",
    region_name=os.getenv("AWS_REGION", "us-east-1")
)

class MedicalRecord(BaseModel):
    id: str
    patient_id: str
    record_type: str  # lab_result | imaging | visit_note | discharge_summary | referral
    title: str
    content: Optional[str]
    s3_key: Optional[str]  # for file attachments
    created_by: str
    created_at: datetime
    is_sensitive: bool  # mental health, substance abuse — extra access controls

class RecordCreate(BaseModel):
    patient_id: str
    record_type: str
    title: str
    content: Optional[str]
    is_sensitive: bool = False

class VisitNote(BaseModel):
    patient_id: str
    chief_complaint: str
    subjective: str      # SOAP note
    objective: str
    assessment: str
    plan: str
    diagnosis_codes: List[str]  # ICD-10
    physician_id: str


async def _check_patient_physician_assignment(patient_id: str, physician_id: str) -> bool:
    """
    Verify that the requesting physician has an active care relationship with
    the patient by checking the appointments / care_team table.

    Returns True when an active assignment exists, False otherwise.

    NOTE: Replace the stub below with a real database query, e.g.:
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
        "_check_patient_physician_assignment must be implemented with a real DB query"
    )


@router.get("/{patient_id}/records", response_model=List[MedicalRecord])
async def get_patient_records(
    patient_id: str,
    record_type: Optional[str] = None,
    current_user: TokenData = Depends(get_current_user)
):
    """
    Patients can view their own records.
    Clinical staff can view assigned patients.
    Sensitive records (42 CFR Part 2 — mental health / substance abuse)
    additionally require the psychiatrist or addiction_specialist role.
    """
    # --- 1. Identity-based access ---
    is_own_record = (
        current_user.role == "patient"
        and current_user.user_id == patient_id
    )

    is_clinical_staff = current_user.role in {"doctor", "nurse", "admin",
                                               "psychiatrist", "addiction_specialist"}

    if not is_own_record and not is_clinical_staff:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: insufficient role"
        )

    # --- 2. Physician-patient assignment check for doctor/specialist roles ---
    if current_user.role in {"doctor", "psychiatrist", "addiction_specialist"}:
        try:
            assigned = await _check_patient_physician_assignment(
                patient_id, current_user.user_id
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

    # --- 3. Fetch records (stub — replace with real DB query) ---
    # records = await db.fetch(
    #     "SELECT * FROM medical_records WHERE patient_id = $1"
    #     + (" AND record_type = $2" if record_type else ""),
    #     *([patient_id, record_type] if record_type else [patient_id])
    # )
    records: List[MedicalRecord] = []  # TODO: replace with real DB fetch

    # --- 4. Filter sensitive records: 42 CFR Part 2 elevated-role check ---
    accessible_records = []
    for rec in records:
        if rec.is_sensitive:
            # Patients may always view their own sensitive records
            if is_own_record:
                accessible_records.append(rec)
            elif current_user.role in SENSITIVE_RECORD_ROLES:
                accessible_records.append(rec)
            else:
                # Do not raise — silently omit to avoid confirming record existence
                continue
        else:
            accessible_records.append(rec)

    return accessible_records


@router.post("/{patient_id}/records", response_model=MedicalRecord)
async def create_record(
    patient_id: str,
    record: RecordCreate,
    current_user: TokenData = Depends(require_role("doctor", "nurse"))
):
    """Create a new medical record entry."""
    # Sensitive records may only be created by elevated roles
    if record.is_sensitive and current_user.role not in SENSITIVE_RECORD_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Creating sensitive (42 CFR Part 2) records requires "
                   "psychiatrist or addiction_specialist role"
        )
    pass

@router.post("/{patient_id}/records/upload")
async def upload_record_file(
    patient_id: str,
    file: UploadFile = File(...),
    record_type: str = "imaging",
    background_tasks: BackgroundTasks = None,
    current_user: TokenData = Depends(require_role("doctor", "nurse", "admin"))
):
    """
    Upload medical file (PDF, DICOM, image) to S3 with KMS encryption.
    File is scanned for malware in background task.
    """
    allowed_types = ["application/pdf", "image/jpeg", "image/png", "application/dicom"]
    if file.content_type not in allowed_types:
        raise HTTPException(status_code=400, detail="File type not allowed")

    s3_key = f"patients/{patient_id}/records/{file.filename}"

    # Upload with server-side encryption
    s3.upload_fileobj(
        file.file,
        S3_BUCKET,
        s3_key,
        ExtraArgs={
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": S3_KMS_KEY,
            "ContentType": file.content_type
        }
    )

    # Trigger malware scan async
    background_tasks.add_task(scan_file_for_malware, s3_key)

    return {"s3_key": s3_key, "status": "uploaded"}

@router.get("/{patient_id}/records/{record_id}/download")
async def get_record_download_url(
    patient_id: str,
    record_id: str,
    current_user: TokenData = Depends(get_current_user)
):
    """Generate presigned S3 URL for file download (expires in 15 min)."""
    url = s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": S3_BUCKET, "Key": f"patients/{patient_id}/records/{record_id}"},
        ExpiresIn=900
    )
    return {"download_url": url}

@router.post("/{patient_id}/visit-notes", response_model=MedicalRecord)
async def create_visit_note(
    patient_id: str,
    note: VisitNote,
    current_user: TokenData = Depends(require_role("doctor"))
):
    """Create SOAP visit note with ICD-10 diagnosis codes."""
    pass

@router.post("/{patient_id}/records/{record_id}/share")
async def share_record(
    patient_id: str,
    record_id: str,
    share_with_provider_id: str,
    current_user: TokenData = Depends(get_current_user)
):
    """Patient authorizes sharing a specific record with another provider."""
    pass

async def scan_file_for_malware(s3_key: str):
    """Background task — triggers ClamAV scan via Lambda."""
    pass
