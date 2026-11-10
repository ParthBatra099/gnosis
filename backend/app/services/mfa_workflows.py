"""Unit 6 orchestration. Every operation runs in an explicit caller transaction."""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol
import secrets
import uuid

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
import pyotp
from sqlalchemy import select, update

from app.core.config import settings
from app.core.security import hash_password, verify_password
from app.models import AuditEvent, AuthenticationChallenge, MFACredential, RecoveryCode, SecurityEvent, User
from app.services.authentication_challenges import (
    ChallengePurpose as Purpose, ChallengeTicket, consume_challenge, create_challenge,
    record_challenge_failure, validate_challenge,
)
from app.services.authentication_common import AuthenticationError, audit, clock, current_user, locked_state, utc
from app.services.authentication_rate_limits import RateLimitPolicy, record_attempt
from app.services.authentication_recovery import consume_recovery_code, hash_recovery_code, store_recovery_hash
from app.services.authentication_sessions import create_session, invalidate_user_sessions, TOTPVerification
from app.services.mfa_encryption import MFASecretCipher
from app.services.totp_verification import TOTPVerificationProvider, accepted_step, generator, plaintext_secret

# A dummy hash equalizes the expensive password path for unknown accounts. This
# random process-local value is not a user credential or a persistent fallback.
_dummy_password_hash = hash_password(secrets.token_urlsafe(32))


@dataclass(frozen=True)
class EnrollmentAuthorization:
    user_id: str
    challenge_id: str
    security_generation: int
    authorization_reference: str
    verified_by: str
    expires_at: datetime


class EnrollmentAuthorizer(Protocol):
    """Trusted independent identity verification, not password/role/JSON claims.

    Deployment-owned code must verify independently authenticated evidence and
    revocation/expiry for this exact subject/challenge. No default issuer exists.
    Applies equally to initial Super Admin enrollment. Never supplied by HTTP.
    """
    def authorize_enrollment(self, db, *, user_id, challenge) -> EnrollmentAuthorization: ...


@dataclass(repr=False)
class Outcome:
    allowed: bool
    payload: dict = field(default_factory=dict, repr=False)
    principal: object = field(default=None, repr=False)


def failure(db, *, user_id=None, action="AUTHENTICATION_FAILED", stage):
    # Unknown-account failures deliberately use the same public response.
    event = AuditEvent(actor_id=user_id, action=action, outcome="DENY", reason="AUTHENTICATION_FAILED",
                      context_data={"stage": stage})
    db.add(event)
    db.flush()
    if action == "AUTH_RATE_LIMIT_ENFORCED":
        db.add(SecurityEvent(actor_id=user_id, event_type=action, severity="MEDIUM", source_audit_id=event.id,
                             description="Authentication attempt budget exhausted"))
        db.flush()
    return Outcome(False)


def throttle(db, *, source, stage, account=None, challenge_id=None):
    categories = [("PASSWORD_SOURCE", source)]  # Shared source budget for all auth operations.
    if stage == "password":
        categories.append(("PASSWORD_ACCOUNT", account))
    else:
        categories.append(("RECOVERY_CHALLENGE" if stage == "recovery" else "ENROLLMENT_CHALLENGE" if stage == "enroll" else "MFA_CHALLENGE", challenge_id))
        user_id = db.scalar(select(AuthenticationChallenge.user_id).where(AuthenticationChallenge.id == challenge_id))
        if user_id:
            categories.append(("RECOVERY_ACCOUNT" if stage == "recovery" else "MFA_ACCOUNT", user_id))
    decisions = [record_attempt(db, category, identifier, now=clock(), policy=
        RateLimitPolicy(settings.AUTH_SOURCE_RATE_LIMIT_THRESHOLD, settings.AUTH_RATE_LIMIT_WINDOW_SECONDS)
        if category == "PASSWORD_SOURCE" else None) for category, identifier in categories]
    if not all(decision.allowed for decision in decisions):
        failure(db, stage=stage, action="AUTH_RATE_LIMIT_ENFORCED")
        return False
    return True


def ticket_payload(ticket, purpose):
    return Outcome(True, {"next_step": purpose.value, "challenge_id": ticket.challenge_id,
                          "challenge_secret": ticket.secret})


def password_login(db, email, password, *, recover=False):
    # Avoid Enum ORM deserialization before neutral password failure handling.
    user = db.execute(select(User.id, User.password_hash, User.active).where(User.email == email)).one_or_none()
    try:
        valid = verify_password(password, user.password_hash if user else _dummy_password_hash)
    except Exception:
        valid = False
    if not valid or user is None or not user.active:
        return failure(db, user_id=user.id if user else None, stage="password", action="AUTH_PASSWORD_FAILED")
    try:
        current_user(db, user.id)
    except AuthenticationError:
        return failure(db, user_id=user.id, stage="password", action="AUTH_PASSWORD_FAILED")
    state = locked_state(db, user.id, initialize=True, now=clock())
    # Recheck after the identity lock: cooperating credential changes cannot race.
    user = db.query(User).filter_by(id=user.id).populate_existing().one()
    if not user.active or not verify_password(password, user.password_hash):
        return failure(db, user_id=user.id, stage="password", action="AUTH_PASSWORD_FAILED")
    active = db.scalar(select(MFACredential.id).where(MFACredential.user_id == user.id, MFACredential.status == "ACTIVE"))
    purpose = Purpose.ACCOUNT_RECOVERY if recover and active else Purpose.MFA_VERIFICATION if active else Purpose.MFA_ENROLLMENT
    audit(db, user_id=user.id, action="AUTH_PASSWORD_VERIFIED")
    return ticket_payload(create_challenge(db, user.id, purpose, now=clock()), purpose)


def _challenge(db, ticket, permitted):
    challenge = db.query(AuthenticationChallenge).filter_by(id=ticket.challenge_id).populate_existing().first()
    if challenge is None or challenge.purpose not in {purpose.value for purpose in permitted}:
        raise AuthenticationError("Authentication failed")
    locked_state(db, challenge.user_id)
    view = validate_challenge(db, challenge.user_id, ticket, challenge.purpose, now=clock())
    return view


def _authorize_enrollment(db, view, authorizer):
    if view.purpose is Purpose.REPLACEMENT_ENROLLMENT:
        receipt = db.query(AuditEvent.id).filter(AuditEvent.action == "AUTH_RECOVERY_AUTHORIZED",
            AuditEvent.context_data["target_user_id"].as_string() == view.user_id,
            AuditEvent.context_data["replacement_challenge_id"].as_string() == view.challenge_id,
            AuditEvent.context_data["security_generation"].as_integer() == view.security_generation).first()
        if receipt is None:
            raise AuthenticationError("Authentication failed")
        reference, verified_by = "RECOVERY_PASSWORD_AND_CODE", "SERVER_VERIFIED_RECOVERY"
    else:
        if authorizer is None or not callable(getattr(authorizer, "authorize_enrollment", None)):
            raise AuthenticationError("Independent enrollment authorization is required")
        authorization = authorizer.authorize_enrollment(db, user_id=view.user_id, challenge=view)
        if (not isinstance(authorization, EnrollmentAuthorization) or authorization.user_id != view.user_id
                or authorization.challenge_id != view.challenge_id or authorization.security_generation != view.security_generation
                or utc(authorization.expires_at) <= clock() or utc(authorization.expires_at) > view.expires_at
                or any(not isinstance(value, str) or not value.strip() or len(value) > 128 for value in
                       (authorization.authorization_reference, authorization.verified_by))
                or authorization.verified_by == view.user_id):
            raise AuthenticationError("Independent enrollment authorization is invalid")
        reference, verified_by = authorization.authorization_reference, authorization.verified_by
    audit(db, user_id=view.user_id, action="AUTH_ENROLLMENT_AUTHORIZED", metadata={
        "challenge_id": view.challenge_id, "security_generation": view.security_generation,
        "authorization_reference": reference, "verified_by": verified_by})


def _obsolete_challenges(db, user_id, except_id):
    db.execute(update(AuthenticationChallenge).where(AuthenticationChallenge.user_id == user_id,
        AuthenticationChallenge.id != except_id, AuthenticationChallenge.consumed_at.is_(None),
        AuthenticationChallenge.revoked_at.is_(None)).values(revoked_at=clock()).execution_options(synchronize_session=False))


def start_enrollment(db, ticket, *, authorizer=None):
    view = _challenge(db, ticket, {Purpose.MFA_ENROLLMENT, Purpose.REPLACEMENT_ENROLLMENT})
    _authorize_enrollment(db, view, authorizer)
    if view.purpose is Purpose.MFA_ENROLLMENT and db.scalar(select(MFACredential.id).where(
            MFACredential.user_id == view.user_id, MFACredential.status == "ACTIVE")):
        raise AuthenticationError("Authentication failed")
    existing = db.query(MFACredential).filter_by(user_id=view.user_id, status="PENDING").with_for_update().all()
    for credential in existing:
        same = db.query(AuditEvent.id).filter(AuditEvent.action == "AUTH_ENROLLMENT_STARTED",
            AuditEvent.context_data["challenge_id"].as_string() == view.challenge_id,
            AuditEvent.context_data["credential_id"].as_string() == credential.id).first()
        if same:
            raise AuthenticationError("Enrollment has already started")
        credential.status, credential.revoked_at, credential.revocation_reason = "REVOKED", clock(), "ENROLLMENT_SUPERSEDED"
    db.flush()
    _obsolete_challenges(db, view.user_id, view.challenge_id)
    credential_id = str(uuid.uuid4())
    secret = pyotp.random_base32()  # 160-bit CSPRNG secret; interoperable SHA-1 TOTP.
    encrypted = MFASecretCipher.from_settings().encrypt(secret.encode("ascii"), user_id=view.user_id, credential_id=credential_id)
    db.add(MFACredential(id=credential_id, user_id=view.user_id, secret_ciphertext=encrypted.ciphertext,
        key_version=encrypted.key_version, status="PENDING", enrolled_at=clock()))
    audit(db, user_id=view.user_id, action="AUTH_ENROLLMENT_STARTED", metadata={
        "challenge_id": view.challenge_id, "credential_id": credential_id, "security_generation": view.security_generation})
    user = db.query(User).filter_by(id=view.user_id).one()
    uri = generator(secret).provisioning_uri(name=user.email, issuer_name=settings.MFA_TOTP_ISSUER)
    return Outcome(True, {"provisioning_uri": uri, "qr_payload": uri, "next_step": "VERIFY_ENROLLMENT"})


def _failed_totp(db, view, ticket):
    record_challenge_failure(db, view.user_id, ticket, view.purpose, now=clock())
    return failure(db, user_id=view.user_id, action="AUTH_TOTP_FAILED", stage="totp")


def _inventory(db, user_id, *, replacement=False):
    # Unique random values before independent Argon2id salts/hashes are computed.
    codes = set()
    while len(codes) < settings.MFA_RECOVERY_CODE_COUNT:
        codes.add(secrets.token_urlsafe(24))
    for code in codes:
        store_recovery_hash(db, user_id, hash_recovery_code(code), now=clock())
    audit(db, user_id=user_id, action="AUTH_RECOVERY_INVENTORY_REGENERATED" if replacement else "AUTH_RECOVERY_INVENTORY_ISSUED",
          metadata={"count": len(codes)})
    return sorted(codes)


def confirm_enrollment(db, ticket, code, *, authorizer=None):
    view = _challenge(db, ticket, {Purpose.MFA_ENROLLMENT, Purpose.REPLACEMENT_ENROLLMENT})
    _authorize_enrollment(db, view, authorizer)
    credential = db.query(MFACredential).filter_by(user_id=view.user_id, status="PENDING").with_for_update().first()
    if credential is None or not db.query(AuditEvent.id).filter(AuditEvent.action == "AUTH_ENROLLMENT_STARTED",
            AuditEvent.context_data["challenge_id"].as_string() == view.challenge_id,
            AuditEvent.context_data["credential_id"].as_string() == credential.id,
            AuditEvent.context_data["security_generation"].as_integer() == view.security_generation).first():
        raise AuthenticationError("Authentication failed")
    try:
        accepted_step(plaintext_secret(credential), code, now=clock(), previous_step=credential.last_accepted_step)
    except AuthenticationError:
        return _failed_totp(db, view, ticket)
    replacement = view.purpose is Purpose.REPLACEMENT_ENROLLMENT
    session_ticket = ticket
    if replacement:
        consume_challenge(db, view.user_id, ticket, view.purpose, now=clock())
        invalidate_user_sessions(db, view.user_id, actor_user_id=view.user_id, reason="MFA_REPLACED", now=clock())
        db.execute(update(MFACredential).where(MFACredential.user_id == view.user_id, MFACredential.status == "ACTIVE")
            .values(status="REVOKED", revoked_at=clock(), revocation_reason="MFA_REPLACED").execution_options(synchronize_session=False))
        session_ticket = create_challenge(db, view.user_id, Purpose.MFA_VERIFICATION, now=clock())
    elif db.scalar(select(MFACredential.id).where(MFACredential.user_id == view.user_id, MFACredential.status == "ACTIVE")):
        raise AuthenticationError("Authentication failed")
    credential.status, credential.activated_at = "ACTIVE", clock()
    audit(db, user_id=view.user_id, action="AUTH_MFA_REPLACED" if replacement else "AUTH_ENROLLMENT_COMPLETED",
          metadata={"credential_id": credential.id, "challenge_id": view.challenge_id})
    principal = create_session(db, view.user_id, session_ticket,
        verifier=TOTPVerificationProvider(credential.id, code, clock()), now=clock())
    audit(db, user_id=view.user_id, action="AUTH_TOTP_VERIFIED")
    _obsolete_challenges(db, view.user_id, session_ticket.challenge_id)
    return Outcome(True, {"authenticated": True, "recovery_codes": _inventory(db, view.user_id, replacement=replacement)}, principal)


def verify_mfa(db, ticket, code):
    view = _challenge(db, ticket, {Purpose.MFA_VERIFICATION})
    credential = db.query(MFACredential).filter_by(user_id=view.user_id, status="ACTIVE").with_for_update().first()
    if credential is None:
        raise AuthenticationError("Authentication failed")
    provider = TOTPVerificationProvider(credential.id, code, clock())
    try:
        provider.verify_for_session(db, user_id=view.user_id, challenge=view)
    except AuthenticationError:
        return _failed_totp(db, view, ticket)
    principal = create_session(db, view.user_id, ticket, verifier=provider, now=clock())
    audit(db, user_id=view.user_id, action="AUTH_TOTP_VERIFIED")
    return Outcome(True, {"authenticated": True}, principal)


def recover_account(db, ticket, candidate):
    view = _challenge(db, ticket, {Purpose.ACCOUNT_RECOVERY})
    codes = db.query(RecoveryCode).filter_by(user_id=view.user_id, security_generation=view.security_generation, consumed_at=None).limit(17).all()
    if len(codes) > 16:
        raise AuthenticationError("Authentication failed")
    matched = []
    if 20 <= len(candidate) <= 256:
        for code in codes:
            try:
                if PasswordHasher().verify(code.code_hash, candidate):
                    matched.append(code.id)
            except (VerificationError, InvalidHashError):
                pass
    if len(matched) != 1:
        record_challenge_failure(db, view.user_id, ticket, view.purpose, now=clock())
        return failure(db, user_id=view.user_id, action="AUTH_RECOVERY_FAILED", stage="recovery")
    consume_challenge(db, view.user_id, ticket, view.purpose, now=clock())
    consume_recovery_code(db, view.user_id, matched[0], candidate, now=clock())
    generation = invalidate_user_sessions(db, view.user_id, actor_user_id=view.user_id, reason="ACCOUNT_RECOVERY", now=clock())
    replacement = create_challenge(db, view.user_id, Purpose.REPLACEMENT_ENROLLMENT, now=clock())
    audit(db, user_id=view.user_id, action="AUTH_RECOVERY_AUTHORIZED", metadata={
        "replacement_challenge_id": replacement.challenge_id, "security_generation": generation})
    return ticket_payload(replacement, Purpose.REPLACEMENT_ENROLLMENT)
