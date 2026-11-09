"""LOCAL_DEMO_PASSWORD_ONLY. Process-local capabilities, never MFA principals."""
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import timedelta
import secrets
from threading import RLock
from uuid import uuid5

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import verify_password
from app.models import AuditEvent, User
from app.services.authentication_common import AuthenticationError, audit, clock, fingerprint, locked_state
from app.services.identity_service import read_identity_state
from app.services import demo_bootstrap as provenance
from app.services.session_management import require_scope

MODE = "LOCAL_DEMO_PASSWORD_ONLY"


@dataclass
class DemoSession:
    subject_user_id: str
    authentication_context_id: str = field(repr=False)
    run_id: str
    security_generation: int
    identity_revision: str
    created_at: object
    expires_at: object
    idle_expires_at: object
    last_activity_at: object
    revoked: bool = False
    auth_mode: str = MODE


class DemoSessions:
    def __init__(self, manifest, target, *, absolute_seconds=1800, idle_seconds=900):
        if not 1 <= idle_seconds <= absolute_seconds <= 1800:
            raise ValueError("Invalid demo session lifetimes")
        self.manifest, self.target = manifest, target
        self.run_id = secrets.token_urlsafe(32)
        self.rate_key = secrets.token_bytes(32)
        self.csrf_key = secrets.token_bytes(32)
        self.absolute_seconds, self.idle_seconds = absolute_seconds, idle_seconds
        self.sessions = {}
        self.invalidated = False
        self.user_locks = {str(u.id): RLock() for u in manifest.users}
        self.wait_seconds = 5
        self.max_active_per_user = 20
        self.max_retained_per_user = 100
        # Global lock protects memory only. Database/password work uses bounded,
        # ordered per-user locks; cooperating identity writers also use DB locks.
        self.lock = RLock()

    def ensure_live(self):
        with self.lock:
            if self.invalidated:
                raise AuthenticationError("Demo run invalidated; restart and verify target")

    def invalidate(self):
        with self.lock:
            self.invalidated = True
            self.sessions.clear()

    def verify_live_target(self, db):
        self.ensure_live()
        try:
            provenance.verify_target(db, self.target)
        except Exception:
            self.invalidate()
            raise AuthenticationError("Demo target cannot be verified; run invalidated") from None
        self.ensure_live()

    @contextmanager
    def operation(self, bind, *user_ids):
        """One connection/transaction, then memory publication after commit.

        Callbacks only change memory; no SQL or expensive work under global lock.
        Per-user locks remain held through commit/publication, including revokes.
        """
        acquired = []
        try:
            self.ensure_live()
            for user_id in sorted(set(user_ids)):
                lock = self.user_locks.get(user_id)
                if lock is not None:
                    if not lock.acquire(timeout=self.wait_seconds):
                        raise HTTPException(503, "Demo authentication busy")
                    acquired.append(lock)
            with Session(bind, autoflush=False) as db:
                with db.begin():
                    self.verify_live_target(db)
                    # Match organization_management.mutation's database row order,
                    # not merely the order of the process-local locks. Acquire the
                    # complete actor/target set before validate/locked_state can
                    # lock either identity individually. Subsequent locks reenter
                    # rows already held by this transaction.
                    if user_ids:
                        db.execute(select(User.id).where(User.id.in_(set(user_ids)))
                                   .order_by(User.id).with_for_update()).all()
                    yield db
                    self.ensure_live()
                with self.lock:
                    self.ensure_live()
                    for publish in db.info.get("demo_publish", ()):
                        publish()
        finally:
            for lock in reversed(acquired):
                lock.release()

    def snapshot(self, sid):
        with self.lock:
            self.ensure_live()
            row = self.sessions.get(sid)
            return replace(row) if row is not None else None

    def user_for(self, sid):
        row = self.snapshot(sid)
        return row.subject_user_id if row else ""

    def revoke_id(self, sid):
        return str(uuid5(self.target.instance_id, "demo-revoke:" + self.run_id + ":" + fingerprint(sid)))

    def publish_login(self, session):
        self.ensure_live()
        now = clock()
        # Retain bounded recent session metadata; durable audit evidence is never deleted.
        rows = [s for s in self.sessions.values() if s.subject_user_id == session.subject_user_id]
        disposable = sorted((s for s in rows if s.revoked or min(s.expires_at, s.idle_expires_at) <= now),
                            key=lambda s: s.created_at)
        for old in disposable:
            if len(rows) < self.max_retained_per_user:
                break
            self.sessions.pop(old.authentication_context_id, None)
            rows.remove(old)
        self.sessions[session.authentication_context_id] = session

    def publish_activity(self, sid, now):
        row = self.sessions.get(sid)
        if row is not None and not row.revoked:
            row.last_activity_at = max(row.last_activity_at, now)
            row.idle_expires_at = min(row.expires_at, row.last_activity_at + timedelta(seconds=self.idle_seconds))

    def publish_revocation(self, rows):
        for row in rows:
            current = self.sessions.get(row.authentication_context_id)
            if current is not None:
                current.revoked = True

    def validate(self, db, sid, *, touch=False):
        session = self.snapshot(sid)
        now = clock()
        if (session is None or session.run_id != self.run_id or session.revoked
                or min(session.expires_at, session.idle_expires_at) <= now):
            raise AuthenticationError("Invalid demo session")
        # Audit evidence is also a durable deny record. If commit succeeded but
        # its acknowledgement was lost, registry publication cannot undo revoke.
        if db.get(AuditEvent, self.revoke_id(sid)) is not None:
            raise AuthenticationError("Revoked demo session")
        try:
            user = provenance.eligible(db, self.manifest, self.target, session.subject_user_id)
            state = locked_state(db, user.id)
            if (state.security_generation != session.security_generation
                    or read_identity_state(db, user.id).revision != session.identity_revision):
                raise AuthenticationError("Demo identity changed")
        except ValueError:
            raise AuthenticationError("Invalid demo identity") from None
        if touch:
            db.info.setdefault("demo_publish", []).append(lambda: self.publish_activity(sid, now))
        return session

    def prepare_login(self, db, email, password):
        user = db.scalar(select(User).where(User.email == email))
        if user is None:
            raise AuthenticationError("Authentication failed")
        state = locked_state(db, user.id, initialize=True)
        with self.lock:
            active = sum(s.subject_user_id == user.id and not s.revoked
                         and min(s.expires_at, s.idle_expires_at) > clock() for s in self.sessions.values())
            if active >= self.max_active_per_user:
                raise HTTPException(429, "Demo active session limit reached")
        try:
            user = provenance.eligible(db, self.manifest, self.target, user.id)
            if not verify_password(password, user.password_hash):
                raise ValueError()
        except Exception:
            raise AuthenticationError("Authentication failed") from None
        now = clock()
        session = DemoSession(user.id, secrets.token_urlsafe(32), self.run_id, state.security_generation,
            read_identity_state(db, user.id).revision, now, now + timedelta(seconds=self.absolute_seconds),
            now + timedelta(seconds=self.idle_seconds), now)
        audit(db, user_id=user.id, action="DEMO_SESSION_CREATED", metadata={
            "auth_mode": MODE, "run_id": self.run_id, "instance_id": str(self.target.instance_id),
            "session_ref": fingerprint(session.authentication_context_id), "password_verified": True})
        db.info.setdefault("demo_publish", []).append(lambda: self.publish_login(session))
        return session  # caller must commit before adding to registry

    def inventory(self, db, actor, target, current, *, limit=20, offset=0):
        require_scope(db, actor, target)
        with self.lock:
            rows = sorted((replace(s) for s in self.sessions.values() if s.subject_user_id == target),
                          key=lambda s: (s.created_at, s.authentication_context_id), reverse=True)
        items = []
        for s in rows[offset:offset + limit]:
            state = "REVOKED" if s.revoked else "EXPIRED" if min(s.expires_at, s.idle_expires_at) <= clock() else "ACTIVE"
            if state == "ACTIVE":
                try:
                    self.validate(db, s.authentication_context_id)
                except AuthenticationError:
                    state = "INVALIDATED"
            items.append(dict(session_ref=fingerprint(s.authentication_context_id), created_at=s.created_at,
                last_activity_at=s.last_activity_at, expires_at=s.expires_at, state=state,
                is_current=secrets.compare_digest(current, s.authentication_context_id)))
        return dict(items=items, total=len(rows), limit=limit, offset=offset)

    def prepare_revocation(self, db, actor, target, current, *, session_ref=None, reason):
        require_scope(db, actor, target, mutation=True)
        principal = self.validate(db, current)
        if principal.subject_user_id != actor:
            raise AuthenticationError("Invalid actor")
        with self.lock:
            rows = [replace(s) for s in self.sessions.values() if s.subject_user_id == target
                    and (session_ref is None or secrets.compare_digest(fingerprint(s.authentication_context_id), session_ref))]
        if not rows and session_ref is not None:
            raise HTTPException(404, {"code": "NOT_FOUND"})
        for row in rows:
            marker_id = self.revoke_id(row.authentication_context_id)
            if db.get(AuditEvent, marker_id) is None:
                db.add(AuditEvent(id=marker_id, actor_id=actor, action="DEMO_SESSION_REVOKED", outcome="ALLOW",
                    reason="AUTHENTICATION_STATE", context_data={"target_user_id": target,
                    "auth_mode": MODE, "run_id": self.run_id, "reason": reason,
                    "session_ref": fingerprint(row.authentication_context_id)}))
                db.flush()
        db.info.setdefault("demo_publish", []).append(lambda: self.publish_revocation(rows))
        return rows  # caller commits first, then marks revoked under the same lock
