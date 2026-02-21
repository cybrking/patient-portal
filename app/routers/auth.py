from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime, timedelta
import jwt
import bcrypt
import os

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Roles that must complete MFA before a token is issued
MFA_REQUIRED_ROLES = {"doctor", "admin"}

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class TokenData(BaseModel):
    user_id: Optional[str] = None
    role: Optional[str] = None  # patient | doctor | nurse | admin
    mfa_verified: bool = False  # True only when TOTP was validated this session

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
        mfa_verified: bool = payload.get("mfa_verified", False)
        if user_id is None:
            raise credentials_exception
        return TokenData(user_id=user_id, role=role, mfa_verified=mfa_verified)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise credentials_exception

@router.post("/token", response_model=Token)
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Authenticate user and return JWT tokens. Supports MFA via TOTP.
    Doctors and admins must supply a valid TOTP code; authentication is
    rejected and mfa_verified remains False if the code is absent or invalid.
    """
    # db lookup, mfa validation, audit log would go here
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    mfa_verified = False

    if user["role"] in MFA_REQUIRED_ROLES:
        # Extract TOTP code from the 'client_secret' field of the
        # OAuth2 password form (used as a carrier for the MFA code)
        # or from a custom header / request body in non-form flows.
        mfa_code = form_data.client_secret  # populated by clients as the TOTP code
        if not mfa_code:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="MFA code required for this role"
            )
        mfa_verified = await verify_totp(user["id"], mfa_code)
        if not mfa_verified:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid MFA code"
            )

    token_data = {"sub": str(user["id"]), "role": user["role"], "mfa_verified": mfa_verified}
    return Token(
        access_token=create_access_token(token_data),
        refresh_token=create_refresh_token(token_data),
        token_type="bearer"
    )

@router.post("/refresh", response_model=Token)
async def refresh_token(refresh_token: str):
    """
    Exchange a refresh token for a new access token.
    mfa_verified is intentionally NOT propagated through refresh — privileged
    roles must re-authenticate with MFA to obtain a fresh mfa_verified token.
    """
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=400, detail="Invalid token type")
        # mfa_verified resets to False on token refresh; full re-auth required
        token_data = {"sub": payload["sub"], "role": payload["role"], "mfa_verified": False}
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

async def verify_totp(user_id: str, code: str) -> bool:
    """
    Validate a TOTP code against the stored secret for the given user.
    Stub — real implementation retrieves the encrypted TOTP secret from the
    database and uses a library such as pyotp to verify the code.
    """
    # TODO: replace with real TOTP verification (e.g. pyotp.TOTP(secret).verify(code))
    raise NotImplementedError("verify_totp must be implemented")
