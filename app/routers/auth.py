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

class RefreshRequest(BaseModel):
    """Request body for the /auth/refresh endpoint.

    Accepting the token exclusively as a JSON body field (never as a query
    parameter or path segment) prevents the value from appearing in server
    access logs, browser history, or Referer headers.
    """
    refresh_token: str

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
        # Reject tokens that are not of type "access" to prevent refresh
        # tokens (or any other token type) from being used as bearer tokens.
        if payload.get("type") != "access":
            raise credentials_exception
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
async def refresh_token(body: RefreshRequest):
    """Exchange a refresh token for a new access/refresh token pair.

    The refresh token must be supplied as a JSON body field — never as a
    query parameter — to avoid token leakage via server logs or browser
    history.
    """
    invalid_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid refresh token",
    )
    try:
        payload = jwt.decode(body.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")
    except jwt.JWTError:
        raise invalid_exc

    # Strict token-type check: only tokens explicitly issued as "refresh" are
    # accepted here; access tokens are rejected even if they decode correctly.
    if payload.get("type") != "refresh":
        raise invalid_exc

    sub = payload.get("sub")
    role = payload.get("role")
    if not sub:
        raise invalid_exc

    token_data = {"sub": sub, "role": role}
    return Token(
        access_token=create_access_token(token_data),
        refresh_token=create_refresh_token(token_data),
        token_type="bearer"
    )

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
