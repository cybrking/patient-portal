"""Field-level encryption for PHI stored in PostgreSQL.

Uses Fernet (AES-128-CBC + HMAC-SHA256) from the `cryptography` package.
Set SSN_ENCRYPTION_KEY to a URL-safe base64-encoded 32-byte key.
Generate one with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""
import os
from cryptography.fernet import Fernet, InvalidToken

_KEY_ENV_VAR = "SSN_ENCRYPTION_KEY"


def _get_fernet() -> Fernet:
    key = os.getenv(_KEY_ENV_VAR)
    if not key:
        raise RuntimeError(
            f"Environment variable {_KEY_ENV_VAR} is not set. "
            "Cannot encrypt/decrypt PHI fields."
        )
    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt_phi(plaintext: str) -> str:
    """Encrypt a plaintext PHI string; returns a URL-safe base64 token."""
    fernet = _get_fernet()
    return fernet.encrypt(plaintext.encode()).decode()


def decrypt_phi(token: str) -> str:
    """Decrypt a Fernet token back to plaintext PHI.

    Raises ValueError for tokens that fail authentication/decryption.
    """
    fernet = _get_fernet()
    try:
        return fernet.decrypt(token.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("PHI decryption failed: invalid or tampered token") from exc
