from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, date
from app.routers.auth import get_current_user, TokenData
from app.routers.patients import require_role
import httpx
import os

router = APIRouter()

TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
TELEHEALTH_SERVICE_URL = os.getenv("TELEHEALTH_SERVICE_URL")

class Appointment(BaseModel):
    id: str
    patient_id: str
    physician_id: str
    appointment_type: str   # in_person | telehealth | phone
    status: str             # scheduled | confirmed | checked_in | completed | cancelled | no_show
    scheduled_at: datetime
    duration_minutes: int
    reason: str
    location: Optional[str]
    telehealth_room_url: Optional[str]
    notes: Optional[str]

class AppointmentCreate(BaseModel):
    physician_id: str
    appointment_type: str
    scheduled_at: datetime
    duration_minutes: int = 30
    reason: str
    location: Optional[str] = None

class TelehealthSession(BaseModel):
    appointment_id: str
    room_url: str
    token: str
    expires_at: datetime

@router.get("/", response_model=List[Appointment])
async def get_appointments(
    start_date: Optional[date] = None,
    end_date: Optional[date] = None,
    current_user: TokenData = Depends(get_current_user)
):
    """Patients see own appointments. Doctors see their schedule."""
    pass

@router.post("/", response_model=Appointment, status_code=201)
async def book_appointment(
    appt: AppointmentCreate,
    background_tasks: BackgroundTasks,
    current_user: TokenData = Depends(get_current_user)
):
    """
    Book appointment. Checks physician availability.
    Sends confirmation email + SMS reminder.
    Creates telehealth room if appointment_type == telehealth.
    """
    # Create appointment record
    # Send confirmation
    background_tasks.add_task(send_confirmation_email, current_user.user_id, appt)
    background_tasks.add_task(schedule_sms_reminder, current_user.user_id, appt)

    if appt.appointment_type == "telehealth":
        room = await create_telehealth_room(appt)
        # attach room URL to appointment

    pass

@router.get("/{appointment_id}/telehealth", response_model=TelehealthSession)
async def get_telehealth_session(
    appointment_id: str,
    current_user: TokenData = Depends(get_current_user)
):
    """
    Generate short-lived token for telehealth video room.
    Uses Daily.co or Twilio Video under the hood.
    Token expires when appointment window closes.
    """
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{TELEHEALTH_SERVICE_URL}/rooms/{appointment_id}/tokens",
            headers={"Authorization": f"Bearer {os.getenv('TELEHEALTH_API_KEY')}"},
            json={"identity": current_user.user_id, "ttl": 3600}
        )
        response.raise_for_status()
    return response.json()

@router.put("/{appointment_id}/cancel")
async def cancel_appointment(
    appointment_id: str,
    reason: Optional[str] = None,
    current_user: TokenData = Depends(get_current_user)
):
    """Cancel appointment. Sends cancellation notification."""
    pass

@router.put("/{appointment_id}/check-in")
async def check_in(
    appointment_id: str,
    current_user: TokenData = Depends(require_role("nurse", "admin"))
):
    """Front desk / nurse checks patient in."""
    pass

@router.get("/availability/{physician_id}")
async def get_physician_availability(
    physician_id: str,
    start_date: date,
    end_date: date,
    current_user: TokenData = Depends(get_current_user)
):
    """Return open appointment slots for a physician."""
    pass

async def create_telehealth_room(appt: AppointmentCreate) -> dict:
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{TELEHEALTH_SERVICE_URL}/rooms",
            headers={"Authorization": f"Bearer {os.getenv('TELEHEALTH_API_KEY')}"},
            json={"name": f"appt-{appt.scheduled_at.isoformat()}"}
        )
        return response.json()

async def send_confirmation_email(user_id: str, appt: AppointmentCreate):
    """Send via SendGrid."""
    pass

async def schedule_sms_reminder(user_id: str, appt: AppointmentCreate):
    """Schedule 24hr reminder via Twilio."""
    pass
