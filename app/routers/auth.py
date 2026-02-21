from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime, timedelta
import jwt
import bcrypt
import os
import logging

logger = logging.getLogger(__name__)

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Known weak / default secret values that must never be used in any environment.
_KNOWN_WEAK_SECRETS = {
    "dev-secret-change-in-production",
    "secret",
    "changeme",
    "your-secret-key",
    "jwt-secret",
    "supersecret",
    "development",
    "test",
}

_MIN_SECRET_BYTES = 32


def _load_and_validate_secret() -> str:
    """
    Load JWT_SECRET_KEY from the environment and enforce minimum security
    requirements at import time so the application refuses to start when
    the secret is absent or dangerously weak.

    Raises RuntimeError on any validation failure — this is intentional:
    a misconfigured secret must prevent the process from starting rather
    than silently issuing tokens that could grant access to patient data.
    """
    secret = os.getenv("JWT_SECRET_KEY", "")

    if not secret:
        raise RuntimeError(
            "JWT_SECRET_KEY environment variable is not set. "
            "The application cannot start without a strong secret key."
        )

    if len(secret.encode()) < _MIN_SECRET_BYTES:
        raise RuntimeError(
            f"JWT_SECRET_KEY is too short ({len(secret.encode())} bytes). "
            f"A minimum of {_MIN_SECRET_BYTES} bytes is required."
        )

    if secret.lower() in _KNOWN_WEAK_SECRETS:
        raise RuntimeError(
            "JWT_SECRET_KEY matches a known default/development value and "
            "must not be used. Set a cryptographically random secret."
        )

    return secret


# Validated at module load — startup fails fast if configuration is unsafe.
SECRET_KEY: str = _load_and_validate_secret()


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
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        # Use a constant-time identical error message to prevent user enumeration.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )

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


async def authenticate_user(email: str, password: str) -> Optional[dict]:
    """
    Look up a user by email in the database and verify the supplied password
    against the stored bcrypt hash.

    Returns the user dict on success, or None on any failure so that the
    caller can return a uniform 401 without leaking which field was wrong.

    NOTE: Replace the `db` import and query below with your actual async
    database client (e.g. asyncpg, SQLAlchemy async, databases, etc.).
    The structure shown here is intentional — do NOT revert to a stub.
    """
    try:
        # --- Replace this block with your real DB query ---
        # Example using a hypothetical `db` singleton:
        #
        # from app.database import db
        # row = await db.fetchrow(
        #     "SELECT id, role, password_hash FROM users WHERE email = $1 AND is_active = TRUE",
        #     email,
        # )
        # if row is None:
        #     return None
        # stored_hash: str = row["password_hash"]
        # if not bcrypt.checkpw(password.encode(), stored_hash.encode()):
        #     return None
        # return {"id": str(row["id"]), "role": row["role"]}
        # --------------------------------------------------

        # Until the database layer is wired up, raise so callers always get
        # a 401 rather than accidentally accepting any credentials.
        raise NotImplementedError(
            "authenticate_user is not yet connected to a database. "
            "Wire up a real DB query before deploying."
        )
    except NotImplementedError:
        raise
    except Exception:
        # Log the exception for diagnostics but never surface internal detail
        # to the caller — return None to produce a generic 401.
        logger.exception("Unexpected error during user authentication for email=%s", email)
        return None
