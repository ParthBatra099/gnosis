"""Additive authentication storage; registration does not enable MFA or sessions."""
from datetime import datetime, timezone
import uuid

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, LargeBinary, String, func, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def identifier():
    return str(uuid.uuid4())


def now():
    return datetime.now(timezone.utc)


class UserAuthenticationState(Base):
    __tablename__ = "user_authentication_states"
    __table_args__ = (
        CheckConstraint("security_generation >= 0", name="ck_auth_state_generation"),
        CheckConstraint("updated_at >= created_at", name="ck_auth_state_time"),
    )
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="RESTRICT"), primary_key=True)
    security_generation: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default=text("0"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now, server_default=func.now())
    user = relationship("User")


class MFACredential(Base):
    __tablename__ = "mfa_credentials"
    __table_args__ = (
        CheckConstraint("status IN ('PENDING', 'ACTIVE', 'REVOKED')", name="ck_mfa_status"),
        CheckConstraint("length(secret_ciphertext) > 28 AND length(key_version) > 0", name="ck_mfa_encrypted_secret"),
        CheckConstraint("last_accepted_step IS NULL OR last_accepted_step >= 0", name="ck_mfa_step"),
        CheckConstraint("activated_at IS NULL OR activated_at >= enrolled_at", name="ck_mfa_activation_time"),
        CheckConstraint("revoked_at IS NULL OR revoked_at >= enrolled_at", name="ck_mfa_revocation_time"),
        CheckConstraint(
            "(status = 'PENDING' AND activated_at IS NULL AND revoked_at IS NULL AND revocation_reason IS NULL) OR "
            "(status = 'ACTIVE' AND activated_at IS NOT NULL AND revoked_at IS NULL AND revocation_reason IS NULL) OR "
            "(status = 'REVOKED' AND revoked_at IS NOT NULL AND revocation_reason IS NOT NULL)", name="ck_mfa_lifecycle"),
        Index("uq_mfa_active_user", "user_id", unique=True, postgresql_where=text("status = 'ACTIVE'"), sqlite_where=text("status = 'ACTIVE'")),
        Index("uq_mfa_pending_user", "user_id", unique=True, postgresql_where=text("status = 'PENDING'"), sqlite_where=text("status = 'PENDING'")),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identifier)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True)
    secret_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_version: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="PENDING")
    enrolled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revocation_reason: Mapped[str | None] = mapped_column(String(64))
    last_accepted_step: Mapped[int | None] = mapped_column(Integer)
    user = relationship("User")


class AuthenticationChallenge(Base):
    __tablename__ = "authentication_challenges"
    __table_args__ = (
        CheckConstraint("purpose IN ('MFA_ENROLLMENT', 'MFA_VERIFICATION', 'ACCOUNT_RECOVERY', 'REPLACEMENT_ENROLLMENT')", name="ck_auth_challenge_purpose"),
        CheckConstraint(
            "(purpose = 'REPLACEMENT_ENROLLMENT' AND challenge_type = 'RECOVERY_VERIFIED') OR "
            "(purpose <> 'REPLACEMENT_ENROLLMENT' AND challenge_type = 'PASSWORD_VERIFIED')", name="ck_auth_challenge_type"),
        CheckConstraint("security_generation >= 0", name="ck_auth_challenge_generation"),
        CheckConstraint("attempts >= 0 AND max_attempts > 0 AND attempts <= max_attempts", name="ck_auth_challenge_attempts"),
        CheckConstraint("expires_at > created_at", name="ck_auth_challenge_expiry"),
        CheckConstraint("length(token_hash) = 64", name="ck_auth_challenge_hash"),
        CheckConstraint("consumed_at IS NULL OR consumed_at >= created_at", name="ck_auth_challenge_consumption_time"),
        CheckConstraint("revoked_at IS NULL OR revoked_at >= created_at", name="ck_auth_challenge_revocation_time"),
        CheckConstraint("consumed_at IS NULL OR revoked_at IS NULL", name="ck_auth_challenge_terminal"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identifier)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True)
    challenge_type: Mapped[str] = mapped_column(String(32), nullable=False)
    purpose: Mapped[str] = mapped_column(String(32), nullable=False)
    security_generation: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default=text("0"))
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    user = relationship("User")


class AuthenticationSession(Base):
    __tablename__ = "authentication_sessions"
    __table_args__ = (
        CheckConstraint("length(id) >= 43", name="ck_auth_session_opaque_id"),
        CheckConstraint("security_generation >= 0", name="ck_auth_session_generation"),
        CheckConstraint("mfa_method = 'TOTP'", name="ck_auth_session_mfa_method"),
        CheckConstraint("mfa_verified_at <= created_at", name="ck_auth_session_verification_time"),
        CheckConstraint("expires_at > created_at", name="ck_auth_session_expiry"),
        CheckConstraint("last_activity_at >= created_at AND last_activity_at < expires_at", name="ck_auth_session_activity"),
        CheckConstraint("idle_expires_at > last_activity_at AND idle_expires_at <= expires_at", name="ck_auth_session_idle"),
        CheckConstraint("(revoked_at IS NULL AND revocation_reason IS NULL) OR (revoked_at IS NOT NULL AND revocation_reason IS NOT NULL AND revoked_at >= created_at)", name="ck_auth_session_revocation"),
    )
    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # CSPRNG, not a raw signed bearer token
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True)
    credential_id: Mapped[str] = mapped_column(String(36), ForeignKey("mfa_credentials.id", ondelete="RESTRICT"), nullable=False)
    challenge_id: Mapped[str] = mapped_column(String(36), ForeignKey("authentication_challenges.id", ondelete="RESTRICT"), nullable=False, unique=True)
    security_generation: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    last_activity_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    idle_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    mfa_verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    mfa_method: Mapped[str] = mapped_column(String(20), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revocation_reason: Mapped[str | None] = mapped_column(String(64))
    user = relationship("User")
    credential = relationship("MFACredential")
    challenge = relationship("AuthenticationChallenge")


class RecoveryCode(Base):
    __tablename__ = "recovery_codes"
    __table_args__ = (
        CheckConstraint("code_hash LIKE '$argon2id$%' AND length(code_hash) >= 80", name="ck_recovery_hash_format"),
        CheckConstraint("security_generation >= 0", name="ck_recovery_generation"),
        CheckConstraint("consumed_at IS NULL OR consumed_at >= created_at", name="ck_recovery_consumption_time"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identifier)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True)
    code_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    security_generation: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    user = relationship("User")


class AuthenticationRateLimit(Base):
    __tablename__ = "authentication_rate_limits"
    __table_args__ = (
        CheckConstraint("length(bucket_key) = 64", name="ck_auth_limit_key"),
        CheckConstraint("category IN ('PASSWORD_ACCOUNT', 'PASSWORD_SOURCE', 'MFA_ACCOUNT', 'MFA_CHALLENGE', 'RECOVERY_ACCOUNT', 'RECOVERY_CHALLENGE', 'ENROLLMENT_CHALLENGE')", name="ck_auth_limit_category"),
        CheckConstraint("attempts > 0 AND threshold > 0 AND attempts <= threshold + 1 AND window_seconds > 0", name="ck_auth_limit_counter"),
        CheckConstraint("expires_at > window_started_at", name="ck_auth_limit_expiry"),
    )
    bucket_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    threshold: Mapped[int] = mapped_column(Integer, nullable=False)
    window_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    window_started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
