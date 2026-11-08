from datetime import datetime, timedelta, timezone
import jwt
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher

from app.core.config import settings

# Initialize Argon2 password hasher
password_hash_context = PasswordHash((Argon2Hasher(),))


def hash_password(password: str) -> str:
    """Hash password using Argon2id."""
    return password_hash_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against Argon2id hash."""
    return password_hash_context.verify(plain_password, hashed_password)


def create_access_token(subject: str, expires_delta: timedelta | None = None, *, session_id: str | None = None) -> str:
    """Sign transport claims; only a valid persisted MFA session grants access.

    A token without sid is intentionally rejected by the authentication dependency.
    Only the completed MFA workflow calls this with a newly committed session.
    """
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    payload = {
        "sub": str(subject),
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    if session_id is not None:
        payload["sid"] = session_id

    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    """Decode and validate JWT access token."""
    return jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
