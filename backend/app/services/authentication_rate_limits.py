"""Shared atomic fixed-window admission counters. No in-process fallback."""
from dataclasses import dataclass
from datetime import timedelta
from enum import Enum
import hashlib
import hmac
import math
import unicodedata

from sqlalchemy import and_, case, or_
from sqlalchemy.exc import SQLAlchemyError

from app.core.config import settings
from app.models import AuthenticationRateLimit
from app.services.authentication_common import AuthenticationError, clock, require_transaction, utc
from app.services.mfa_encryption import decode_managed_key


class RateLimitCategory(str, Enum):
    PASSWORD_ACCOUNT = "PASSWORD_ACCOUNT"
    PASSWORD_SOURCE = "PASSWORD_SOURCE"
    MFA_ACCOUNT = "MFA_ACCOUNT"
    MFA_CHALLENGE = "MFA_CHALLENGE"
    RECOVERY_ACCOUNT = "RECOVERY_ACCOUNT"
    RECOVERY_CHALLENGE = "RECOVERY_CHALLENGE"
    ENROLLMENT_CHALLENGE = "ENROLLMENT_CHALLENGE"


class RateLimitUnavailable(AuthenticationError):
    pass


@dataclass(frozen=True)
class RateLimitPolicy:
    threshold: int
    window_seconds: int

    def __post_init__(self):
        if any(type(value) is not int or not 1 <= value <= 1_000_000 for value in (self.threshold, self.window_seconds)):
            raise AuthenticationError("Invalid authentication rate-limit policy")

    @classmethod
    def configured(cls):
        return cls(settings.AUTH_RATE_LIMIT_THRESHOLD, settings.AUTH_RATE_LIMIT_WINDOW_SECONDS)


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    attempts: int
    remaining: int
    retry_after_seconds: int


def bucket_key(category, identifier, *, key=None):
    category = RateLimitCategory(category)
    if key is None:
        if settings.AUTH_RATE_LIMIT_KEY is None:
            raise RateLimitUnavailable("Managed authentication rate-limit key is required")
        try:
            key = decode_managed_key(settings.AUTH_RATE_LIMIT_KEY.get_secret_value())
        except ValueError:
            raise RateLimitUnavailable("Authentication rate-limit configuration is invalid") from None
    if not isinstance(key, bytes) or len(key) != 32:
        raise RateLimitUnavailable("Authentication rate-limit key is invalid")
    if not isinstance(identifier, str) or not 1 <= len(identifier) <= 512:
        raise AuthenticationError("Invalid authentication rate-limit identifier")
    normalized = unicodedata.normalize("NFKC", identifier).strip().casefold()
    if not normalized or any(unicodedata.category(char).startswith("C") for char in normalized):
        raise AuthenticationError("Invalid authentication rate-limit identifier")
    # Only normalized account IDs/emails, challenge IDs or source identifiers.
    # Callers must never pass passwords, OTPs, recovery codes or bearer tokens.
    return hmac.new(key, f"gnosis:auth-limit:v1:{category.value}:{normalized}".encode(), hashlib.sha256).hexdigest()


def record_attempt(db, category, identifier, *, policy=None, key=None, now=None):
    """Caller commits the returned decision before denying an HTTP request.

    A denied attempt saturates at threshold+1 rather than overflowing. A changed
    policy within a live bucket fails closed; expired buckets adopt the new policy.
    """
    require_transaction(db)
    category = RateLimitCategory(category)
    policy = policy or RateLimitPolicy.configured()
    digest = bucket_key(category, identifier, key=key)
    timestamp = clock(now)
    dialect = db.get_bind().dialect.name
    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    elif dialect == "sqlite":
        from sqlalchemy.dialects.sqlite import insert
    else:
        raise RateLimitUnavailable("Unsupported authentication rate-limit storage")
    table = AuthenticationRateLimit.__table__
    expired = table.c.expires_at <= timestamp
    statement = insert(table).values(bucket_key=digest, category=category.value, attempts=1,
        threshold=policy.threshold, window_seconds=policy.window_seconds, window_started_at=timestamp,
        expires_at=timestamp + timedelta(seconds=policy.window_seconds))
    statement = statement.on_conflict_do_update(index_elements=[table.c.bucket_key], set_={
        "attempts": case((expired, 1), (table.c.attempts < table.c.threshold + 1, table.c.attempts + 1), else_=table.c.attempts),
        "window_started_at": case((expired, timestamp), else_=table.c.window_started_at),
        "expires_at": case((expired, timestamp + timedelta(seconds=policy.window_seconds)), else_=table.c.expires_at),
        "threshold": case((expired, policy.threshold), else_=table.c.threshold),
        "window_seconds": case((expired, policy.window_seconds), else_=table.c.window_seconds),
    }, where=and_(table.c.category == category.value, or_(expired, and_(
        table.c.threshold == policy.threshold, table.c.window_seconds == policy.window_seconds))))
    statement = statement.returning(table.c.attempts, table.c.expires_at)
    try:
        row = db.execute(statement).one_or_none()
    except SQLAlchemyError:
        raise RateLimitUnavailable("Authentication rate-limit storage is unavailable") from None
    if row is None:
        raise RateLimitUnavailable("Authentication rate-limit policy conflicts with persisted state")
    allowed = row.attempts <= policy.threshold
    return RateLimitDecision(allowed, row.attempts, max(0, policy.threshold - row.attempts),
                             0 if allowed else max(1, math.ceil((utc(row.expires_at) - timestamp).total_seconds())))
