"""Persisted MFA session primitives. Not wired into existing JWT authentication."""
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import secrets
from typing import Protocol

from sqlalchemy import or_, select, update

from app.core.config import settings
from app.models import AuthenticationChallenge, AuthenticationSession, MFACredential, UserAuthenticationState
from app.services.authentication_challenges import ChallengePurpose, ChallengeTicket, ChallengeView, consume_challenge, validate_challenge
from app.services.authentication_common import (
    AuthenticationError, RevocationReason, audit, clock, current_user, fingerprint, locked_state, utc,
)


@dataclass(frozen=True)
class SessionPolicy:
    absolute_seconds: int
    idle_seconds: int
    verification_max_age_seconds: int

    def __post_init__(self):
        if (any(type(value) is not int or value <= 0 for value in (
                self.absolute_seconds, self.idle_seconds, self.verification_max_age_seconds))
                or self.idle_seconds > self.absolute_seconds):
            raise AuthenticationError("Invalid session policy")

    @classmethod
    def configured(cls):
        return cls(settings.AUTH_SESSION_ABSOLUTE_SECONDS, settings.AUTH_SESSION_IDLE_SECONDS,
                   settings.AUTH_VERIFICATION_MAX_AGE_SECONDS)


@dataclass(frozen=True)
class TOTPVerification:
    """Data returned ONLY by the trusted Unit 6 verifier, not an HTTP proof format."""
    user_id: str
    challenge_id: str
    security_generation: int
    credential_id: str
    verified_at: datetime
    accepted_step: int


class SessionVerificationProvider(Protocol):
    """Unit 6 must implement real verification. No default implementation exists.

    The provider authenticates TOTP against the persisted active credential for
    the exact challenge. It returns a fresh result without committing or reserving
    the replay step itself. Password/recovery-code-only providers are forbidden.
    A provider is server-owned code, never selected/deserialized from request data.
    """
    def verify_for_session(self, db, *, user_id: str, challenge: ChallengeView) -> TOTPVerification: ...


@dataclass(frozen=True)
class SessionPrincipal:
    """Snapshot satisfying Unit 3's structural TrustedPrincipalContext contract.

    Obtain anew through validation per request; possession/constructor is no proof.
    """
    subject_user_id: str
    authentication_context_id: str = field(repr=False)
    security_generation: int
    mfa_verified_at: datetime
    expires_at: datetime


def create_session(db, user_id, ticket, *, verifier: SessionVerificationProvider | None = None,
                   policy=None, now=None):
    timestamp = clock(now)
    policy = policy or SessionPolicy.configured()
    if verifier is None or not callable(getattr(verifier, "verify_for_session", None)):
        raise AuthenticationError("Trusted TOTP verification is required to create a session")
    if not isinstance(ticket, ChallengeTicket):
        raise AuthenticationError("A restricted authentication challenge is required")
    state = locked_state(db, user_id)
    challenge = db.query(AuthenticationChallenge).filter_by(id=ticket.challenge_id).populate_existing().first()
    if challenge is None or challenge.purpose == ChallengePurpose.ACCOUNT_RECOVERY.value:
        raise AuthenticationError("A recovery challenge cannot create a full session")
    view = validate_challenge(db, user_id, ticket, challenge.purpose, now=timestamp)
    proof = verifier.verify_for_session(db, user_id=user_id, challenge=view)
    if (not isinstance(proof, TOTPVerification) or proof.user_id != user_id
            or proof.challenge_id != view.challenge_id or type(proof.security_generation) is not int
            or proof.security_generation != state.security_generation
            or type(proof.accepted_step) is not int or proof.accepted_step < 0
            or not max(utc(challenge.created_at), timestamp - timedelta(seconds=policy.verification_max_age_seconds))
                   <= utc(proof.verified_at) <= timestamp):
        raise AuthenticationError("Trusted TOTP verification is invalid or stale")
    credential = db.query(MFACredential).filter_by(id=proof.credential_id).with_for_update().populate_existing().first()
    if (credential is None or credential.user_id != user_id or credential.status != "ACTIVE"
            or credential.revoked_at is not None or credential.activated_at is None
            or utc(credential.activated_at) > utc(proof.verified_at)):
        raise AuthenticationError("Verified MFA credential is not active")
    if (view.purpose in {ChallengePurpose.MFA_ENROLLMENT, ChallengePurpose.REPLACEMENT_ENROLLMENT}
            and utc(credential.enrolled_at) < utc(challenge.created_at)):
        raise AuthenticationError("Enrollment requires a new MFA credential for this challenge")
    # Atomic replay reservation and challenge consumption share the session/audit
    # transaction. Two competing issuances cannot accept the same time step.
    consume_challenge(db, user_id, ticket, view.purpose, now=timestamp)
    accepted = db.execute(update(MFACredential).where(
        MFACredential.id == credential.id, MFACredential.status == "ACTIVE", MFACredential.revoked_at.is_(None),
        or_(MFACredential.last_accepted_step.is_(None), MFACredential.last_accepted_step < proof.accepted_step),
    ).values(last_accepted_step=proof.accepted_step).returning(MFACredential.id)
      .execution_options(synchronize_session=False)).scalar_one_or_none()
    if accepted is None:
        raise AuthenticationError("MFA verification step was already accepted")
    expires_at = timestamp + timedelta(seconds=policy.absolute_seconds)
    session = AuthenticationSession(id=secrets.token_urlsafe(32), user_id=user_id, credential_id=credential.id,
        challenge_id=view.challenge_id, security_generation=state.security_generation, created_at=timestamp,
        expires_at=expires_at, last_activity_at=timestamp,
        idle_expires_at=min(expires_at, timestamp + timedelta(seconds=policy.idle_seconds)),
        mfa_verified_at=utc(proof.verified_at), mfa_method="TOTP")
    db.add(session)
    db.flush()
    audit(db, user_id=user_id, action="AUTH_SESSION_CREATED", metadata={
        "session_ref": fingerprint(session.id), "security_generation": state.security_generation, "method": "TOTP"})
    return SessionPrincipal(user_id, session.id, state.security_generation, utc(proof.verified_at), expires_at)


def validate_session(db, subject_user_id, session_id, *, touch=False, policy=None, now=None):
    """Persisted state is mandatory. No role/MFA JWT claims are accepted here.

    The future dependency must independently authenticate transport/signature first.
    touch=True requires an explicit transaction and serializes with revocation.
    """
    timestamp = clock(now)
    policy = policy or SessionPolicy.configured()
    if not isinstance(session_id, str) or not 43 <= len(session_id) <= 64:
        raise AuthenticationError("A persisted MFA session is required")
    current_user(db, subject_user_id)
    if touch:
        locked_state(db, subject_user_id)
    state_generation = db.scalar(select(UserAuthenticationState.security_generation).where(
        UserAuthenticationState.user_id == subject_user_id))
    query = db.query(AuthenticationSession).filter_by(id=session_id, user_id=subject_user_id)
    if touch:
        query = query.with_for_update()
    session = query.populate_existing().first()
    if (session is None or state_generation is None or session.security_generation != state_generation
            or session.revoked_at is not None or session.mfa_method != "TOTP" or session.mfa_verified_at is None
            or utc(session.created_at) > timestamp or utc(session.mfa_verified_at) > utc(session.created_at)
            or utc(session.expires_at) <= timestamp or utc(session.idle_expires_at) <= timestamp
            or utc(session.last_activity_at) > timestamp):
        raise AuthenticationError("Session is expired, revoked or invalid")
    credential = db.execute(select(MFACredential.user_id, MFACredential.status, MFACredential.revoked_at,
                                    MFACredential.activated_at, MFACredential.last_accepted_step)
                            .where(MFACredential.id == session.credential_id)).one_or_none()
    if (credential is None or credential.user_id != subject_user_id or credential.status != "ACTIVE"
            or credential.revoked_at is not None or credential.activated_at is None or credential.last_accepted_step is None
            or utc(credential.activated_at) > utc(session.mfa_verified_at)):
        raise AuthenticationError("Session MFA credential is invalid")
    challenge = db.query(AuthenticationChallenge).filter_by(id=session.challenge_id).populate_existing().first()
    if (challenge is None or challenge.user_id != subject_user_id or challenge.security_generation != state_generation
            or challenge.purpose not in {ChallengePurpose.MFA_ENROLLMENT.value, ChallengePurpose.MFA_VERIFICATION.value,
                                         ChallengePurpose.REPLACEMENT_ENROLLMENT.value}
            or challenge.consumed_at is None or challenge.revoked_at is not None
            or not utc(challenge.created_at) <= utc(session.mfa_verified_at) <= utc(challenge.consumed_at) <= utc(session.created_at)
            or utc(challenge.consumed_at) >= utc(challenge.expires_at)):
        raise AuthenticationError("Session verification challenge is invalid")
    if challenge.purpose in {ChallengePurpose.MFA_ENROLLMENT.value, ChallengePurpose.REPLACEMENT_ENROLLMENT.value}:
        enrolled_at = db.scalar(select(MFACredential.enrolled_at).where(MFACredential.id == session.credential_id))
        if enrolled_at is None or utc(enrolled_at) < utc(challenge.created_at):
            raise AuthenticationError("Session enrollment credential is invalid")
    if touch:
        session.last_activity_at = timestamp
        session.idle_expires_at = min(utc(session.expires_at), timestamp + timedelta(seconds=policy.idle_seconds))
        db.flush()
    return SessionPrincipal(subject_user_id, session_id, state_generation, utc(session.mfa_verified_at), utc(session.expires_at))


def revoke_session(db, session_id, *, actor_user_id, reason=RevocationReason.LOGOUT, now=None, operator_reason=None):
    timestamp = clock(now)
    reason = RevocationReason(reason)
    if operator_reason is not None and (not isinstance(operator_reason, str) or not operator_reason.strip() or len(operator_reason) > 2000):
        raise AuthenticationError("A bounded nonempty session-revocation reason is required")
    user_id = db.scalar(select(AuthenticationSession.user_id).where(AuthenticationSession.id == session_id))
    if user_id is None:
        raise AuthenticationError("Session is unavailable")
    locked_state(db, user_id, require_active=False)
    session = db.query(AuthenticationSession).filter_by(id=session_id).with_for_update().populate_existing().one()
    if session.revoked_at is not None:
        return False
    session.revoked_at = timestamp
    session.revocation_reason = reason.value
    audit(db, user_id=user_id, actor_id=actor_user_id, action="AUTH_SESSION_REVOKED",
          metadata={"session_ref": fingerprint(session_id), "cause": reason.value,
                    **({"reason": operator_reason.strip()} if operator_reason is not None else {})})
    return True


def invalidate_user_sessions(db, user_id, *, actor_user_id, reason=RevocationReason.SECURITY_CHANGE, now=None):
    """Internal primitive, not proof of actor authorization. Caller authorizes it."""
    timestamp = clock(now)
    reason = RevocationReason(reason)
    state = locked_state(db, user_id, initialize=True, now=timestamp, require_active=False)
    if timestamp < utc(state.updated_at):
        raise AuthenticationError("Security generation cannot move backwards in time")
    previous = state.security_generation
    state.security_generation += 1
    state.updated_at = timestamp
    db.flush()
    db.execute(update(AuthenticationSession).where(AuthenticationSession.user_id == user_id,
        AuthenticationSession.revoked_at.is_(None)).values(revoked_at=timestamp, revocation_reason=reason.value)
        .execution_options(synchronize_session=False))
    db.execute(update(AuthenticationChallenge).where(AuthenticationChallenge.user_id == user_id,
        AuthenticationChallenge.revoked_at.is_(None), AuthenticationChallenge.consumed_at.is_(None))
        .values(revoked_at=timestamp).execution_options(synchronize_session=False))
    audit(db, user_id=user_id, actor_id=actor_user_id, action="AUTH_GENERATION_CHANGED", metadata={
        "previous_generation": previous, "new_generation": state.security_generation, "cause": reason.value})
    return state.security_generation
