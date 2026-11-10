"""Restricted capabilities only; no challenge grants ordinary application access."""
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import hmac
import secrets

from sqlalchemy import update

from app.core.config import settings
from app.models import AuthenticationChallenge, UserAuthenticationState
from app.services.authentication_common import AuthenticationError, audit, clock, current_user, fingerprint, locked_state, utc


class ChallengePurpose(str, Enum):
    MFA_ENROLLMENT = "MFA_ENROLLMENT"
    MFA_VERIFICATION = "MFA_VERIFICATION"
    ACCOUNT_RECOVERY = "ACCOUNT_RECOVERY"
    REPLACEMENT_ENROLLMENT = "REPLACEMENT_ENROLLMENT"


@dataclass(frozen=True)
class ChallengePolicy:
    lifetime_seconds: int
    max_attempts: int

    def __post_init__(self):
        if any(type(value) is not int or value <= 0 for value in (self.lifetime_seconds, self.max_attempts)):
            raise AuthenticationError("Invalid challenge policy")

    @classmethod
    def configured(cls):
        return cls(settings.AUTH_CHALLENGE_LIFETIME_SECONDS, settings.AUTH_CHALLENGE_MAX_ATTEMPTS)


@dataclass(frozen=True)
class ChallengeTicket:
    challenge_id: str
    secret: str = field(repr=False)


@dataclass(frozen=True)
class ChallengeView:
    challenge_id: str
    user_id: str
    purpose: ChallengePurpose
    security_generation: int
    expires_at: datetime
    failed_attempts: int


def create_challenge(db, user_id, purpose, *, policy=None, now=None):
    """Trusted Unit 6 callers establish the prerequisite verification beforehand.

    REPLACEMENT_ENROLLMENT must only be requested after atomic recovery-code
    consumption, never directly from password verification. This primitive does
    not implement that workflow or verify passwords/codes.
    """
    purpose = ChallengePurpose(purpose)
    policy = policy or ChallengePolicy.configured()
    timestamp = clock(now)
    state = locked_state(db, user_id, initialize=True, now=timestamp)
    secret = secrets.token_urlsafe(32)
    challenge = AuthenticationChallenge(user_id=user_id, token_hash=fingerprint(secret), purpose=purpose.value,
        challenge_type="RECOVERY_VERIFIED" if purpose is ChallengePurpose.REPLACEMENT_ENROLLMENT else "PASSWORD_VERIFIED",
        security_generation=state.security_generation, created_at=timestamp,
        expires_at=timestamp + timedelta(seconds=policy.lifetime_seconds), attempts=0, max_attempts=policy.max_attempts)
    db.add(challenge)
    db.flush()
    audit(db, user_id=user_id, action="AUTH_CHALLENGE_CREATED", metadata={"challenge_id": challenge.id, "purpose": purpose.value})
    return ChallengeTicket(challenge.id, secret)


def validate_challenge(db, user_id, ticket, purpose, *, now=None):
    timestamp = clock(now)
    purpose = ChallengePurpose(purpose)
    current_user(db, user_id)
    if not isinstance(ticket, ChallengeTicket) or not isinstance(ticket.secret, str) or not 43 <= len(ticket.secret) <= 128:
        raise AuthenticationError("Invalid authentication challenge")
    challenge = db.query(AuthenticationChallenge).filter_by(id=ticket.challenge_id).populate_existing().first()
    state = db.query(UserAuthenticationState).filter_by(user_id=user_id).populate_existing().first()
    if (challenge is None or state is None or challenge.user_id != user_id or challenge.purpose != purpose.value
            or challenge.challenge_type != ("RECOVERY_VERIFIED" if purpose is ChallengePurpose.REPLACEMENT_ENROLLMENT else "PASSWORD_VERIFIED")
            or not hmac.compare_digest(challenge.token_hash, fingerprint(ticket.secret))
            or challenge.security_generation != state.security_generation
            or challenge.consumed_at is not None or challenge.revoked_at is not None
            or utc(challenge.created_at) > timestamp or utc(challenge.expires_at) <= timestamp
            or challenge.attempts >= challenge.max_attempts):
        raise AuthenticationError("Invalid authentication challenge")
    return ChallengeView(challenge.id, user_id, purpose, state.security_generation, utc(challenge.expires_at), challenge.attempts)


def consume_challenge(db, user_id, ticket, purpose, *, now=None):
    timestamp = clock(now)
    state = locked_state(db, user_id)
    view = validate_challenge(db, user_id, ticket, purpose, now=timestamp)
    result = db.execute(update(AuthenticationChallenge).where(
        AuthenticationChallenge.id == ticket.challenge_id, AuthenticationChallenge.user_id == user_id,
        AuthenticationChallenge.token_hash == fingerprint(ticket.secret),
        AuthenticationChallenge.purpose == view.purpose.value,
        AuthenticationChallenge.security_generation == state.security_generation,
        AuthenticationChallenge.consumed_at.is_(None), AuthenticationChallenge.revoked_at.is_(None),
        AuthenticationChallenge.expires_at > timestamp,
        AuthenticationChallenge.attempts < AuthenticationChallenge.max_attempts,
    ).values(consumed_at=timestamp).returning(AuthenticationChallenge.id).execution_options(synchronize_session=False)).scalar_one_or_none()
    if result is None:
        raise AuthenticationError("Authentication challenge was already used or invalidated")
    audit(db, user_id=user_id, action="AUTH_CHALLENGE_CONSUMED", metadata={"challenge_id": view.challenge_id, "purpose": view.purpose.value})
    return view


def record_challenge_failure(db, user_id, ticket, purpose, *, now=None):
    """Commit failed-attempt state before returning a verification failure to HTTP.

    Unit 6 must not raise a denial inside this transaction and roll it back.
    Separate shared rate counters also count attempts, including successful ones.
    """
    timestamp = clock(now)
    locked_state(db, user_id)
    view = validate_challenge(db, user_id, ticket, purpose, now=timestamp)
    attempts = db.execute(update(AuthenticationChallenge).where(
        AuthenticationChallenge.id == view.challenge_id, AuthenticationChallenge.user_id == user_id,
        AuthenticationChallenge.token_hash == fingerprint(ticket.secret),
        AuthenticationChallenge.purpose == view.purpose.value,
        AuthenticationChallenge.security_generation == view.security_generation,
        AuthenticationChallenge.consumed_at.is_(None),
        AuthenticationChallenge.revoked_at.is_(None), AuthenticationChallenge.expires_at > timestamp,
        AuthenticationChallenge.attempts < AuthenticationChallenge.max_attempts,
    ).values(attempts=AuthenticationChallenge.attempts + 1).returning(AuthenticationChallenge.attempts)
      .execution_options(synchronize_session=False)).scalar_one_or_none()
    if attempts is None:
        raise AuthenticationError("Authentication challenge is unavailable")
    audit(db, user_id=user_id, action="AUTH_CHALLENGE_FAILED", metadata={"challenge_id": view.challenge_id, "failed_attempts": attempts})
    return attempts
