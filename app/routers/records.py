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

s3 = boto3.client(
    "s3",
    region_name=os.getenv("AWS_REGION", "us-east-1")
)

# Roles that are permitted to access sensitive (mental health / substance abuse) records.
# Admins with a compliance need and doctors are elevated; nurses and plain patients are not.
SENSITIVE_RECORD_ROLES = {"doctor", "admin"}

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


def _verify_patient_access(patient_id: str, current_user: TokenData) -> None:
    """
    Raise HTTP 403 if current_user is not authorised to access records for
    patient_id.

    Authorization rules
    -------------------
    * patient  — may only access their own records (user_id must equal patient_id).
    * doctor   — must be assigned to the patient (verified via is_doctor_assigned_to_patient).
    * nurse    — must be assigned to the patient (same helper).
    * admin    — always permitted (administrative / compliance access).
    * anything else — denied.
    """
    role = current_user.role

    if role == "patient":
        if current_user.user_id != patient_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Patients may only access their own records."
            )

    elif role in ("doctor", "nurse"):
        if not is_clinical_staff_assigned_to_patient(current_user.user_id, patient_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: not assigned to this patient."
            )

    elif role == "admin":
        # Admins have unrestricted read access for compliance purposes.
        pass

    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: insufficient role."
        )


def _verify_sensitive_record_access(current_user: TokenData) -> None:
    """
    Raise HTTP 403 if the caller does not hold an elevated role that permits
    access to sensitive (mental health / substance abuse) records.
    """
    if current_user.role not in SENSITIVE_RECORD_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Access denied: sensitive mental health and substance abuse records "
                "require elevated access privileges."
            )
        )


def is_clinical_staff_assigned_to_patient(staff_id: str, patient_id: str) -> bool:
    """
    Return True when the clinical staff member identified by staff_id has an
    active assignment to the patient identified by patient_id.

    NOTE: This is a stub.  Replace the body with a real database query, e.g.:

        row = db.execute(
            "SELECT 1 FROM patient_assignments "
            "WHERE staff_id = $1 AND patient_id = $2 AND is_active = TRUE",
            staff_id, patient_id
        ).fetchone()
        return row is not None
    """
    # TODO: implement real DB lookup for doctor-patient / nurse-patient assignments.
    raise NotImplementedError(
        "is_clinical_staff_assigned_to_patient must be implemented before use."
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
    Sensitive records (mental health / substance abuse) require elevated access.
    """
    # 1. Verify the caller is allowed to access this patient's records at all.
    _verify_patient_access(patient_id, current_user)

    # 2. Fetch the records from the data store (stub — replace with real DB query).
    #    Apply the optional record_type filter at the query level.
    records: List[MedicalRecord] = fetch_records_from_db(patient_id, record_type)

    # 3. If any returned record is sensitive, verify the caller has elevated access.
    #    We check once up-front rather than per-record to avoid partial data leakage.
    has_sensitive = any(r.is_sensitive for r in records)
    if has_sensitive:
        _verify_sensitive_record_access(current_user)

    return records


def fetch_records_from_db(
    patient_id: str,
    record_type: Optional[str] = None
) -> List[MedicalRecord]:
    """
    Retrieve medical records for patient_id from the database.

    NOTE: This is a stub.  Replace with a real parameterised query, e.g.:

        query = "SELECT * FROM medical_records WHERE patient_id = $1"
        params = [patient_id]
        if record_type:
            query += " AND record_type = $2"
            params.append(record_type)
        return db.execute(query, *params).fetchall()
    """
    # TODO: implement real DB query.
    return []


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
