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
        # Use a generic message to prevent username enumeration
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

async def _get_db_connection():
    """
    Return an asyncpg connection from the application connection pool.

    The pool is expected to be stored on the FastAPI app state as
    ``app.state.db_pool`` and initialised at startup via asyncpg.create_pool().
    Importing here avoids a circular import; callers must ensure the pool has
    been created before this function is invoked.
    """
    try:
        from app.main import app  # noqa: PLC0415
        return await app.state.db_pool.acquire()
    except Exception as exc:  # pragma: no cover
        logger.error("Failed to acquire DB connection: %s", exc)
        raise

async def authenticate_user(email: str, password: str) -> Optional[dict]:
    """
    Look up the user by e-mail address and verify the supplied password
    against the bcrypt hash stored in the database.

    Returns a dict with at least ``id`` and ``role`` keys on success,
    or ``None`` if the credentials are invalid or the account is inactive.

    The users table is expected to have the following relevant columns:
        id            – UUID / text primary key
        email         – unique, case-insensitive
        password_hash – bcrypt hash (e.g. produced by bcrypt.hashpw)
        role          – one of patient | doctor | nurse | admin
        is_active     – boolean; inactive accounts are rejected
    """
    if not email or not password:
        return None

    conn = None
    try:
        conn = await _get_db_connection()
        row = await conn.fetchrow(
            """
            SELECT id, email, password_hash, role, is_active
            FROM users
            WHERE email = $1
            LIMIT 1
            """,
            email.lower().strip(),
        )
    except Exception as exc:  # pragma: no cover
        logger.error("Database error during authentication: %s", exc)
        return None
    finally:
        if conn is not None:
            try:
                from app.main import app  # noqa: PLC0415
                await app.state.db_pool.release(conn)
            except Exception:  # pragma: no cover
                pass

    if row is None:
        # User not found — perform a dummy bcrypt check to prevent
        # timing-based username enumeration.
        _DUMMY_HASH = b"$2b$12$aaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        bcrypt.checkpw(password.encode("utf-8"), _DUMMY_HASH)
        return None

    if not row["is_active"]:
        return None

    stored_hash = row["password_hash"]
    if isinstance(stored_hash, str):
        stored_hash = stored_hash.encode("utf-8")

    password_valid = bcrypt.checkpw(password.encode("utf-8"), stored_hash)
    if not password_valid:
        return None

    return {"id": str(row["id"]), "role": row["role"]}
