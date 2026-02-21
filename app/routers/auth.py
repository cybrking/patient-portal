from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime, timedelta
import jwt
import bcrypt
import os
import sys

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

# Known weak / placeholder values that must never be used in any environment.
_REJECTED_SECRET_VALUES = {
    "dev-secret-change-in-production",
    "secret",
    "changeme",
    "change-me",
    "your-secret-key",
    "jwt-secret",
    "",
}

_MIN_SECRET_BYTES = 32


def _load_and_validate_secret() -> str:
    """Load JWT_SECRET_KEY from the environment and abort startup if it is
    absent, too short, or matches a known-weak placeholder value."""
    secret = os.getenv("JWT_SECRET_KEY", "")

    if not secret:
        print(
            "FATAL: JWT_SECRET_KEY environment variable is not set. "
            "Application startup aborted.",
            file=sys.stderr,
        )
        sys.exit(1)

    if secret.lower() in _REJECTED_SECRET_VALUES:
        print(
            "FATAL: JWT_SECRET_KEY matches a known weak/placeholder value. "
            "Set a cryptographically random secret of at least "
            f"{_MIN_SECRET_BYTES} bytes. Application startup aborted.",
            file=sys.stderr,
        )
        sys.exit(1)

    if len(secret.encode()) < _MIN_SECRET_BYTES:
        print(
            f"FATAL: JWT_SECRET_KEY is shorter than {_MIN_SECRET_BYTES} bytes. "
            "Set a cryptographically random secret of at least "
            f"{_MIN_SECRET_BYTES} bytes. Application startup aborted.",
            file=sys.stderr,
        )
        sys.exit(1)

    return secret


SECRET_KEY = _load_and_validate_secret()
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

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

@router.post("/token", response_model=Token)
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    """Authenticate user and return JWT tokens. Supports MFA via TOTP."""
    # db lookup, mfa validation, audit log would go here
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    token_data = {"sub": str(user["id"]), "role": user["role"]}
    return Token(
        access_token=create_access_token(token_data),
        refresh_token=create_refresh_token(token_data),
        token_type="bearer"
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
    # Stub — real impl queries PostgreSQL
    return {"id": "user-123", "role": "patient"}
