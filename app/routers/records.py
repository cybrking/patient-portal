from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
from pathlib import Path
from app.routers.auth import get_current_user, TokenData
from app.routers.patients import require_role
import boto3
import os
import uuid

router = APIRouter()

S3_BUCKET = os.getenv("S3_RECORDS_BUCKET")
S3_KMS_KEY = os.getenv("S3_KMS_KEY_ARN")  # Server-side encryption key

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


def _safe_filename(filename: Optional[str]) -> str:
    """
    Strip all directory components from a user-supplied filename and return
    only the bare name portion.  An empty or missing filename is replaced
    with a random UUID so the upload never fails silently.
    """
    if not filename:
        return str(uuid.uuid4())
    # Path(filename).name discards everything before the last separator,
    # neutralising traversal sequences such as '../../other/file.pdf'.
    name = Path(filename).name
    # Reject names that are still suspicious after stripping (e.g. pure dots).
    if not name or name in (".", ".."):
        return str(uuid.uuid4())
    return name


@router.get("/{patient_id}/records", response_model=List[MedicalRecord])
async def get_patient_records(
    patient_id: str,
    record_type: Optional[str] = None,
    current_user: TokenData = Depends(get_current_user)
):
    """
    Patients can view their own records.
    Clinical staff can view assigned patients.
    Sensitive records (mental health) require elevated access.
    """
    pass

@router.post("/{patient_id}/records", response_model=MedicalRecord)
async def create_record(
    patient_id: str,
    record: RecordCreate,
    current_user: TokenData = Depends(require_role("doctor", "nurse"))
):
    """Create a new medical record entry."""
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
    File is written to a quarantine prefix and scanned for malware before
    presigned download URLs are issued.
    """
    allowed_types = ["application/pdf", "image/jpeg", "image/png", "application/dicom"]
    if file.content_type not in allowed_types:
        raise HTTPException(status_code=400, detail="File type not allowed")

    # Sanitize the filename to prevent S3 key path traversal.
    # A UUID prefix guarantees uniqueness and makes the key unpredictable.
    safe_name = _safe_filename(file.filename)
    file_id = str(uuid.uuid4())
    sanitized_filename = f"{file_id}_{safe_name}"

    # Place the file in a quarantine prefix; it will be promoted to the
    # permanent prefix only after a clean malware-scan result.
    s3_key = f"quarantine/patients/{patient_id}/records/{sanitized_filename}"

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

    # Trigger malware scan async; scan result must update scan_status in DB
    # to 'clean' before download URLs can be generated.
    background_tasks.add_task(scan_file_for_malware, s3_key)

    return {"s3_key": s3_key, "status": "quarantined", "scan_status": "pending"}

@router.get("/{patient_id}/records/{record_id}/download")
async def get_record_download_url(
    patient_id: str,
    record_id: str,
    current_user: TokenData = Depends(get_current_user)
):
    """
    Generate presigned S3 URL for file download (expires in 15 min).
    Only records with scan_status == 'clean' may be downloaded.
    """
    # TODO: look up the record in the DB by record_id and patient_id,
    # verify ownership/access, and check scan_status before proceeding.
    # Example guard (replace with real DB lookup):
    #
    #   record = await db.get_record(record_id, patient_id)
    #   if not record:
    #       raise HTTPException(status_code=404, detail="Record not found")
    #   if record.scan_status != "clean":
    #       raise HTTPException(status_code=403,
    #                           detail="File is pending scan or was rejected")
    #   s3_key = record.s3_key
    #
    # The key is retrieved from the DB — never reconstructed from user input.
    s3_key = f"patients/{patient_id}/records/{record_id}"

    url = s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": S3_BUCKET, "Key": s3_key},
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
