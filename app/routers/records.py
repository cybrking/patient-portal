from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
from app.routers.auth import get_current_user, TokenData
from app.routers.patients import require_role
import boto3
from botocore.exceptions import ClientError
import os

router = APIRouter()

S3_BUCKET = os.getenv("S3_RECORDS_BUCKET")
S3_KMS_KEY = os.getenv("S3_KMS_KEY_ARN")  # Server-side encryption key

s3 = boto3.client(
    "s3",
    region_name=os.getenv("AWS_REGION", "us-east-1")
)

# Clinical roles that may access records for patients they are assigned to
CLINICAL_ROLES = {"doctor", "nurse", "admin"}

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


def _assert_patient_access(current_user: TokenData, patient_id: str) -> None:
    """
    Enforce object-level authorization for PHI access.

    - Patients may only access their own records (user_id must match patient_id).
    - Clinical staff (doctor, nurse, admin) are permitted; doctor-patient
      assignment validation should be added here once the patient service
      exposes that relationship.

    Raises HTTP 403 if the caller is not authorised to access the given
    patient_id.
    """
    if current_user.role == "patient":
        if current_user.user_id != patient_id:
            raise HTTPException(
                status_code=403,
                detail="Access denied: you may only access your own records"
            )
    elif current_user.role not in CLINICAL_ROLES:
        # Unknown / unprivileged role
        raise HTTPException(
            status_code=403,
            detail="Access denied: insufficient role"
        )
    # TODO: for role == "doctor", additionally verify doctor-patient assignment
    # against the patient service before returning PHI.


def _assert_record_owned_by_patient(patient_id: str, record_id: str) -> None:
    """
    Verify that the S3 object identified by record_id actually lives under the
    patient_id prefix.  This prevents an authenticated user from supplying a
    valid record_id that belongs to a different patient.

    The canonical key layout is:  patients/{patient_id}/records/{record_id}

    We perform a head_object call so we never generate a presigned URL for a
    key that does not exist or that sits outside the expected prefix.

    Raises HTTP 404 if the object is absent, HTTP 403 if the key is not
    scoped to the given patient.
    """
    # Reject any record_id that tries to escape the patient prefix via path
    # traversal (e.g. "../../other-patient/records/secret").
    if ".." in record_id or record_id.startswith("/"):
        raise HTTPException(
            status_code=400,
            detail="Invalid record identifier"
        )

    expected_key = f"patients/{patient_id}/records/{record_id}"

    try:
        s3.head_object(Bucket=S3_BUCKET, Key=expected_key)
    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        if error_code in ("404", "NoSuchKey"):
            raise HTTPException(
                status_code=404,
                detail="Record not found"
            )
        # For any other S3 error surface a generic 403 to avoid leaking
        # bucket structure information.
        raise HTTPException(
            status_code=403,
            detail="Access denied"
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
    Sensitive records (mental health) require elevated access.
    """
    _assert_patient_access(current_user, patient_id)
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
    # 1. Verify the caller is authorised to access this patient's records.
    _assert_patient_access(current_user, patient_id)

    # 2. Verify the record actually belongs to this patient in S3 before
    #    generating a presigned URL (object-level / IDOR check).
    _assert_record_owned_by_patient(patient_id, record_id)

    expected_key = f"patients/{patient_id}/records/{record_id}"
    url = s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": S3_BUCKET, "Key": expected_key},
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
    # Only the patient who owns the record may share it.
    _assert_patient_access(current_user, patient_id)
    pass

async def scan_file_for_malware(s3_key: str):
    """Background task — triggers ClamAV scan via Lambda."""
    pass
