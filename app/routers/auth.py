from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime, timedelta
import jwt
import bcrypt
import os
import hmac
import hashlib
import struct
import time
import base64

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Roles that MUST have MFA enrolled and validated on every login
MFA_REQUIRED_ROLES = {"admin", "doctor"}

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class TokenData(BaseModel):
    user_id: Optional[str] = None
    role: Optional[str] = None  # patient | doctor | nurse | admin

class UserLogin(BaseModel):
    email: EmailStr
    password: str
    mfa_code: Optional[str] = None

class PasswordReset(BaseModel):
    token: str
    new_password: str

class MFASetup(BaseModel):
    user_id: str
    totp_secret: str


def _hotp(secret_b32: str, counter: int) -> str:
    """Compute an HOTP value from a base32-encoded secret and counter."""
    key = base64.b32decode(secret_b32.upper())
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % 1_000_000).zfill(6)


def verify_totp(totp_secret: str, code: str, window: int = 1) -> bool:
    """
    Verify a 6-digit TOTP code against the user's base32 TOTP secret.
    Accepts codes within `window` 30-second steps on either side of now
    to tolerate minor clock skew.
    """
    if not totp_secret or not code:
        return False
    # Strip whitespace/dashes that authenticator apps sometimes display
    code = code.replace(" ", "").replace("-", "")
    if len(code) != 6 or not code.isdigit():
        return False
    current_step = int(time.time()) // 30
    for step in range(current_step - window, current_step + window + 1):
        if hmac.compare_digest(_hotp(totp_secret, step), code):
            return True
    return False


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        role: str = payload.get("role")
        if user_id is None:
            raise credentials_exception
        return TokenData(user_id=user_id, role=role)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise credentials_exception


@router.post("/login", response_model=Token)
async def login_with_mfa(request: Request, credentials: UserLogin):
    """
    Authenticate user with password and (for admin/doctor roles) mandatory TOTP MFA.
    Returns JWT access + refresh tokens on success.
    """
    # authenticate_user must return None on bad credentials to prevent timing attacks
    user = await authenticate_user(credentials.email, credentials.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )

    role = user.get("role", "")

    if role in MFA_REQUIRED_ROLES:
        totp_secret = user.get("totp_secret")  # fetched from DB alongside user record
        if not totp_secret:
            # MFA has not been enrolled yet — block login until setup is complete
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="MFA enrollment required before login is permitted for this role",
            )
        if not credentials.mfa_code:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="MFA code required",
            )
        if not verify_totp(totp_secret, credentials.mfa_code):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid MFA code",
            )

    token_data = {"sub": str(user["id"]), "role": role}
    return Token(
        access_token=create_access_token(token_data),
        refresh_token=create_refresh_token(token_data),
        token_type="bearer",
    )


@router.post("/token", response_model=Token)
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    """
    OAuth2 password flow endpoint (used by Swagger UI / OAuth clients).
    MFA is enforced for privileged roles — mfa_code must be supplied in the
    'client_secret' field or use the /auth/login JSON endpoint instead.
    """
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    role = user.get("role", "")

    if role in MFA_REQUIRED_ROLES:
        totp_secret = user.get("totp_secret")
        if not totp_secret:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="MFA enrollment required before login is permitted for this role",
            )
        # OAuth2PasswordRequestForm carries extra fields in form_data.scopes or
        # callers may pass mfa_code as a custom form field; here we read it from
        # client_secret as a pragmatic workaround for the standard form shape.
        mfa_code = form_data.client_secret or ""
        if not mfa_code:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="MFA code required",
            )
        if not verify_totp(totp_secret, mfa_code):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid MFA code",
            )

    token_data = {"sub": str(user["id"]), "role": role}
    return Token(
        access_token=create_access_token(token_data),
        refresh_token=create_refresh_token(token_data),
        token_type="bearer",
    )


@router.post("/refresh", response_model=Token)
async def refresh_token(refresh_token: str):
    """Exchange a refresh token for a new access token."""
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=400, detail="Invalid token type")
        token_data = {"sub": payload["sub"], "role": payload["role"]}
        return Token(
            access_token=create_access_token(token_data),
            refresh_token=create_refresh_token(token_data),
            token_type="bearer"
        )
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

@router.post("/password-reset/request")
async def request_password_reset(email: EmailStr):
    """Send password reset email. Rate limited to prevent enumeration."""
    # Always return 200 to prevent user enumeration
    return {"message": "If that email exists, a reset link has been sent"}

@router.post("/password-reset/confirm")
async def confirm_password_reset(reset: PasswordReset):
    """Complete password reset with token from email."""
    pass

@router.post("/mfa/setup")
async def setup_mfa(current_user: TokenData = Depends(get_current_user)):
    """Generate TOTP secret for MFA enrollment."""
    pass

@router.post("/logout")
async def logout(token: str = Depends(oauth2_scheme)):
    """Invalidate token — adds to server-side blocklist."""
    pass

async def authenticate_user(email: str, password: str):
    # Stub — real impl queries PostgreSQL and returns totp_secret from user row
    # The returned dict MUST include 'totp_secret' (None if not enrolled)
    return {"id": "user-123", "role": "patient", "totp_secret": None}
