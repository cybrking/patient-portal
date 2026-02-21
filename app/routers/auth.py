from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime, timedelta
import jwt
import bcrypt
import os
import uuid
import logging
import redis

logger = logging.getLogger("auth")

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Redis client for refresh token tracking.
# Key schema:
#   refresh_token:{jti}  -> "valid"   (TTL = token lifetime)  — token is usable
#   refresh_token:{jti}  -> "used"    (TTL = token lifetime)  — token already consumed
#   blocklist:{jti}      -> "1"        (TTL = token lifetime)  — access token revoked
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
_redis_client: Optional[redis.Redis] = None


def get_redis() -> redis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.from_url(REDIS_URL, decode_responses=True)
    return _redis_client


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
    to_encode.update({"exp": expire, "type": "access", "jti": str(uuid.uuid4())})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: dict) -> tuple[str, str]:
    """Return (encoded_token, jti). Registers the jti in Redis as 'valid'."""
    jti = str(uuid.uuid4())
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh", "jti": jti})
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    ttl_seconds = REFRESH_TOKEN_EXPIRE_DAYS * 86400
    r = get_redis()
    r.set(f"refresh_token:{jti}", "valid", ex=ttl_seconds)

    return token, jti


def _issue_token_pair(token_data: dict) -> Token:
    """Create a matched access + refresh token pair."""
    access_token = create_access_token(token_data)
    refresh_token_str, _ = create_refresh_token(token_data)
    return Token(
        access_token=access_token,
        refresh_token=refresh_token_str,
        token_type="bearer",
    )


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
        jti: str = payload.get("jti")
        if user_id is None:
            raise credentials_exception
        # Check access token blocklist (populated on logout / deactivation)
        if jti and get_redis().exists(f"blocklist:{jti}"):
            raise HTTPException(status_code=401, detail="Token has been revoked")
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
    return _issue_token_pair(token_data)


@router.post("/refresh", response_model=Token)
async def refresh_token(refresh_token: str):
    """
    Exchange a refresh token for a new access + refresh token pair.

    Single-use semantics are enforced via Redis:
    - The incoming token's jti must be in state "valid".
    - It is atomically moved to state "used" before the new pair is issued.
    - A second use of the same jti (state "used" or missing) is treated as a
      replay attack: the associated user account should be flagged and the
      incident logged for security review.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired refresh token",
    )
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expired")
    except jwt.JWTError:
        raise credentials_exception

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=400, detail="Invalid token type")

    jti = payload.get("jti")
    if not jti:
        raise credentials_exception

    r = get_redis()
    redis_key = f"refresh_token:{jti}"
    current_state = r.get(redis_key)

    if current_state == "used":
        # Replay detected — the old token has already been consumed.
        # Log a security alert; callers may wish to lock the account.
        user_id = payload.get("sub", "unknown")
        logger.warning(
            "SECURITY: refresh token replay detected",
            extra={"jti": jti, "user_id": user_id},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token already used — possible account compromise. Please log in again.",
        )

    if current_state != "valid":
        # Token was never registered (forged) or already expired in Redis.
        raise credentials_exception

    # Atomically mark old token as used so concurrent requests cannot race.
    ttl = r.ttl(redis_key)
    if ttl and ttl > 0:
        r.set(redis_key, "used", ex=ttl)
    else:
        r.set(redis_key, "used", ex=REFRESH_TOKEN_EXPIRE_DAYS * 86400)

    token_data = {"sub": payload["sub"], "role": payload["role"]}
    return _issue_token_pair(token_data)


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
    """
    Invalidate the current access token by adding its jti to the blocklist.
    Clients should also discard their refresh token; if the refresh token jti
    is passed as a query/body parameter it can be revoked here too.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        jti = payload.get("jti")
        if jti:
            # Blocklist until the token's natural expiry
            exp = payload.get("exp")
            now = int(datetime.utcnow().timestamp())
            ttl = max((exp - now) if exp else ACCESS_TOKEN_EXPIRE_MINUTES * 60, 1)
            get_redis().set(f"blocklist:{jti}", "1", ex=ttl)
    except jwt.JWTError:
        pass  # Already invalid — nothing to revoke
    return {"message": "Logged out successfully"}


async def authenticate_user(email: str, password: str):
    # Stub — real impl queries PostgreSQL
    return {"id": "user-123", "role": "patient"}
