"""Shared caller-owned transaction and audit contract for authentication primitives."""
from datetime import datetime, timezone
from enum import Enum
import hashlib

from sqlalchemy import String, cast, select
from sqlalchemy.orm import SessionTransactionOrigin

from app.core.constants import OrganizationRole
from app.models import AuditEvent, User, UserAuthenticationState
from app.services.identity_service import lock_identity


class AuthenticationError(ValueError):
    pass


class RevocationReason(str, Enum):
    LOGOUT = "LOGOUT"
    USER_REQUEST = "USER_REQUEST"
    SECURITY_CHANGE = "SECURITY_CHANGE"
    PASSWORD_CHANGE = "PASSWORD_CHANGE"
    MFA_REPLACED = "MFA_REPLACED"
    ACCOUNT_RECOVERY = "ACCOUNT_RECOVERY"
    ADMIN_REVOKED = "ADMIN_REVOKED"


def utc(value):
    if not isinstance(value, datetime):
        raise AuthenticationError("A valid timestamp is required")
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def clock(value=None):
    return utc(value) if value is not None else datetime.now(timezone.utc)


def require_transaction(db):
    transaction = db.get_transaction()
    if transaction is None or transaction.origin is not SessionTransactionOrigin.BEGIN:
        raise AuthenticationError("An explicit caller-owned session.begin() transaction is required")
    if db.new or db.dirty or db.deleted:
        raise AuthenticationError("Flush caller changes before authentication primitives")


def current_user(db, user_id):
    row = db.execute(select(User.id, User.active, cast(User.organization_role, String)).where(User.id == user_id)).one_or_none()
    if row is None or not row.active:
        raise AuthenticationError("Authentication identity is unavailable")
    try:
        OrganizationRole(row[2])
    except (ValueError, TypeError):
        raise AuthenticationError("A valid reviewed canonical identity is required") from None
    return row.id


def locked_state(db, user_id, *, initialize=False, now=None, require_active=True):
    require_transaction(db)
    # Scalar validation handles corrupt canonical Enum values before Unit 2's
    # identity snapshot. Invalidation may target inactive/unmapped users as well.
    if require_active:
        current_user(db, user_id)
    # Use the same existing identity lock as Units 2–4, never a parallel framework.
    lock_identity(db, user_id)
    if require_active:
        current_user(db, user_id)
    state = db.query(UserAuthenticationState).filter_by(user_id=user_id).with_for_update().populate_existing().first()
    if state is None:
        if not initialize:
            raise AuthenticationError("Authentication state is unavailable")
        timestamp = clock(now)
        state = UserAuthenticationState(user_id=user_id, security_generation=0,
                                        created_at=timestamp, updated_at=timestamp)
        db.add(state)
        db.flush()
    return state


def audit(db, *, user_id, action, metadata=None, actor_id=None):
    # Only service-selected metadata: never arbitrary credential or prompt values.
    actor_id = actor_id if actor_id is not None else user_id
    if db.scalar(select(User.id).where(User.id == actor_id)) is None:
        raise AuthenticationError("Unknown audit actor")
    db.add(AuditEvent(actor_id=actor_id, action=action, outcome="ALLOW", reason="AUTHENTICATION_STATE",
                      context_data={"target_user_id": user_id, **(metadata or {})}))
    db.flush()  # Audit exceptions must escape the outer transaction.


def fingerprint(value):
    return hashlib.sha256(value.encode()).hexdigest()
