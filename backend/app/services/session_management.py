"""Scoped session inventory and strict targeted revocation; no bearer disclosure."""
import hmac
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.models import AuthenticationSession, User
from app.services.authentication_common import AuthenticationError, clock, fingerprint, utc
from app.services.authentication_sessions import revoke_session, validate_session
from app.services import organization_authority as authority
from app.services.identity_service import lock_identity


def require_scope(db, actor_id, target_id, *, mutation=False):
    # Self-service applies to all authenticated canonical roles. Cross-user session
    # administration is organization-wide identity authority, never department scope.
    if actor_id != target_id:
        check = authority.revalidate_authority_for_mutation if mutation else authority.evaluate_authority
        decision = check(db, actor_id, authority.AdministrativeAction.IDENTITY_ADMINISTER, authority.OrganizationScope())
        if not decision.allowed:
            raise HTTPException(403, {"code": "SESSION_ADMINISTRATION_DENIED"})
    elif mutation:
        lock_identity(db, actor_id)
    if db.scalar(select(User.id).where(User.id == target_id)) is None:
        raise HTTPException(404, {"code": "NOT_FOUND"})


def inventory(db, actor_id, target_id, current_id, *, limit=20, offset=0):
    require_scope(db, actor_id, target_id)
    query = db.query(AuthenticationSession).filter_by(user_id=target_id)
    total = query.count()
    now = clock()
    items = []
    for session in query.order_by(AuthenticationSession.created_at.desc(), AuthenticationSession.id).limit(limit).offset(offset):
        state = "REVOKED" if session.revoked_at else "EXPIRED" if min(utc(session.expires_at), utc(session.idle_expires_at)) <= now else "ACTIVE"
        if state == "ACTIVE":
            try:
                validate_session(db, target_id, session.id, now=now)
            except AuthenticationError:
                state = "INVALIDATED"
        items.append({"session_ref": fingerprint(session.id), "created_at": session.created_at,
                      "last_activity_at": session.last_activity_at, "expires_at": session.expires_at,
                      "state": state, "is_current": hmac.compare_digest(session.id, current_id)})
    return {"items": items, "total": total, "limit": limit, "offset": offset}


def revoke(source, actor_id, target_id, session_ref, reason, actor_session_id):
    # One ordinary existing-bind SQLAlchemy transaction owns state plus audit.
    with Session(bind=source.get_bind(), autoflush=False) as db, db.begin():
        revoke_in_transaction(db, actor_id, target_id, session_ref, reason, actor_session_id)


def revoke_in_transaction(db, actor_id, target_id, session_ref, reason, actor_session_id):
    require_scope(db, actor_id, target_id, mutation=True)
    # The actor lock serializes with session revocation/generation changes too.
    # This is current persisted-session validation, not a new TOTP freshness gate.
    try:
        validate_session(db, actor_id, actor_session_id)
    except AuthenticationError:
        raise HTTPException(401, "Not authenticated") from None
    # Scope precedes digest matching. Public references never authenticate.
    target = None
    for session_id in db.scalars(select(AuthenticationSession.id).where(AuthenticationSession.user_id == target_id)).yield_per(100):
        if hmac.compare_digest(fingerprint(session_id), session_ref):
            target = session_id
            break
    if target is None:
        raise HTTPException(404, {"code": "NOT_FOUND"})
    revoke_session(db, target, actor_user_id=actor_id,
                   reason="USER_REQUEST" if actor_id == target_id else "ADMIN_REVOKED", operator_reason=reason)
