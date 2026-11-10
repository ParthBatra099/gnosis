"""Atomic identity primitives. Callers supply authorization and an explicit transaction.

Use ``with session.begin(): ...`` and allow exceptions to leave that block. These
functions flush, never commit, and never call the best-effort audit/detection path.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from typing import Mapping
from types import MappingProxyType

from sqlalchemy import select, update
from sqlalchemy.orm import Session, SessionTransactionOrigin

from app.core.constants import OrganizationRole
from app.models import AuditEvent, Department, DepartmentAdminAssignment, User

IDENTITY_ACTIONS = (
    "ORGANIZATION_ROLE_CHANGED", "DEPARTMENT_ADMIN_ASSIGNED", "DEPARTMENT_ADMIN_REVOKED",
    "ORGANIZATION_PROFILE_CHANGED", "ORGANIZATION_ACCOUNT_STATUS_CHANGED", "ORGANIZATION_EMPLOYEE_CREATED",
)
PROVENANCE_KEYS = frozenset({
    "manifest_id", "manifest_version", "manifest_sha256", "operator_id", "reviewer_id",
    "reviewer_user_id", "approval_reference", "approval_record_id", "environment_id",
})


class IdentityError(ValueError):
    pass


class StaleIdentityError(IdentityError):
    pass


def utc(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


@dataclass(frozen=True)
class IdentityEvidence:
    actor_id: str
    reason: str
    provenance: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self):
        object.__setattr__(self, "provenance", MappingProxyType(dict(self.provenance)))
        if not self.actor_id.strip() or not self.reason.strip() or len(self.reason) > 2000:
            raise IdentityError("Actor and a bounded nonempty reason are required")
        if set(self.provenance) - PROVENANCE_KEYS:
            raise IdentityError("Unsupported audit provenance fields")
        if any(not isinstance(v, str) or not v.strip() or len(v) > 2000 for v in self.provenance.values()):
            raise IdentityError("Audit provenance must contain bounded nonempty identifiers")


@dataclass(frozen=True)
class IdentityState:
    user_id: str
    organization_role: OrganizationRole | None
    revision: str


def read_identity_state(session: Session, user_id: str) -> IdentityState:
    """Fingerprint current identity/history, including audit IDs to detect role ABA changes."""
    with session.no_autoflush:
        user = session.execute(select(
            User.organization_role, User.role, User.department_id, User.active,
        ).where(User.id == user_id)).one_or_none()
        if user is None:
            raise IdentityError("Unknown target user")
        assignments = session.scalars(select(DepartmentAdminAssignment).where(
            DepartmentAdminAssignment.user_id == user_id,
        ).order_by(DepartmentAdminAssignment.id).execution_options(populate_existing=True)).all()
        audits = session.scalars(select(AuditEvent.id).where(
            AuditEvent.action.in_(IDENTITY_ACTIONS),
            AuditEvent.context_data["target_user_id"].as_string() == user_id,
        ).order_by(AuditEvent.id)).all()
        payload = {
            "user_id": user_id, "role": user.organization_role, "legacy_role": user.role,
            "home_department": user.department_id, "active": user.active, "audit_ids": audits,
            "assignments": [{
                "id": a.id, "department_id": a.department_id, "assigned_by": a.assigned_by,
                "assigned_at": utc(a.assigned_at).isoformat(), "revoked_by": a.revoked_by,
                "revoked_at": utc(a.revoked_at).isoformat() if a.revoked_at else None,
            } for a in assignments],
        }
        revision = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        return IdentityState(user_id, user.organization_role, revision)


def lock_identity(session: Session, user_id: str) -> IdentityState:
    """Serialize cooperating identity writers on the user row; SQLite takes its write lock."""
    transaction = session.get_transaction()
    if transaction is None or transaction.origin is not SessionTransactionOrigin.BEGIN:
        raise IdentityError("An explicit session.begin() transaction is required")
    if session.new or session.dirty or session.deleted:
        raise IdentityError("Flush caller changes before invoking identity primitives")
    # A same-value UPDATE acquires a row write lock on PostgreSQL and a write lock
    # on SQLite. Read state only after this lock; an obsolete SQLite snapshot fails
    # rather than silently overwriting newer identity state.
    result = session.execute(update(User).where(User.id == user_id).values(
        organization_role=User.organization_role,
    ).execution_options(synchronize_session=False))
    if result.rowcount != 1:
        raise IdentityError("Unknown target user")
    return read_identity_state(session, user_id)


def _prepare(session, user_id, expected_revision, evidence):
    state = lock_identity(session, user_id)
    if state.revision != expected_revision:
        raise StaleIdentityError("Identity changed since review; obtain a fresh revision")
    if session.scalar(select(User.id).where(User.id == evidence.actor_id)) is None:
        raise IdentityError("Unknown audit actor")
    return state


def _audit(session, action, target_user_id, previous, new, evidence, department_id=None):
    now = datetime.now(timezone.utc)
    event = AuditEvent(
        actor_id=evidence.actor_id, action=action, outcome="ALLOW", reason="IDENTITY_CHANGE",
        timestamp=now,
        context_data={
            **dict(evidence.provenance), "target_user_id": target_user_id,
            "previous_value": previous, "new_value": new, "department_id": department_id,
            "changed_at": now.isoformat(), "reason": evidence.reason,
        },
    )
    session.add(event)
    session.flush()  # failure invalidates the transaction, including the identity mutation
    return event


def change_organization_role(session, user_id, role, *, expected_revision, evidence):
    role = OrganizationRole(role)  # exact canonical values only; no legacy inference
    state = _prepare(session, user_id, expected_revision, evidence)
    if state.organization_role == role:
        return None
    active = session.scalar(select(DepartmentAdminAssignment.id).where(
        DepartmentAdminAssignment.user_id == user_id, DepartmentAdminAssignment.revoked_at.is_(None),
    ).limit(1))
    if role is not OrganizationRole.DEPARTMENT_ADMIN and active:
        raise IdentityError("Revoke active department assignments before changing this role")
    session.execute(update(User).where(User.id == user_id).values(organization_role=role))
    return _audit(session, IDENTITY_ACTIONS[0], user_id, state.organization_role, role, evidence)


def create_department_admin_assignment(session, user_id, department_id, *, expected_revision, evidence):
    state = _prepare(session, user_id, expected_revision, evidence)
    if state.organization_role is not OrganizationRole.DEPARTMENT_ADMIN:
        raise IdentityError("An explicit canonical DEPARTMENT_ADMIN role is required")
    department_active = session.scalar(select(Department.active).where(Department.id == department_id).with_for_update())
    if department_active is None:
        raise IdentityError("Unknown department")
    if not department_active:
        raise IdentityError("Department must be active before creating an administrative assignment")
    existing = session.scalar(select(DepartmentAdminAssignment).where(
        DepartmentAdminAssignment.user_id == user_id,
        DepartmentAdminAssignment.department_id == department_id,
        DepartmentAdminAssignment.revoked_at.is_(None),
    ))
    if existing:
        return existing
    assignment = DepartmentAdminAssignment(
        user_id=user_id, department_id=department_id, assigned_by=evidence.actor_id,
    )
    session.add(assignment)
    session.flush()
    _audit(session, IDENTITY_ACTIONS[1], user_id, None, {
        "assignment_id": assignment.id, "assigned_by": evidence.actor_id,
        "assigned_at": utc(assignment.assigned_at).isoformat(), "active": True,
    }, evidence, department_id)
    return assignment


def revoke_department_admin_assignment(session, user_id, assignment_id, *, expected_revision, evidence):
    _prepare(session, user_id, expected_revision, evidence)
    assignment = session.scalar(select(DepartmentAdminAssignment).where(
        DepartmentAdminAssignment.id == assignment_id, DepartmentAdminAssignment.user_id == user_id,
    ).execution_options(populate_existing=True))
    if assignment is None:
        raise IdentityError("Unknown assignment for target user")
    if assignment.revoked_at is not None:
        return assignment
    revoked_at = datetime.now(timezone.utc)
    if revoked_at < utc(assignment.assigned_at):
        raise IdentityError("Revocation cannot precede assignment creation")
    assignment.revoked_at = revoked_at
    assignment.revoked_by = evidence.actor_id
    _audit(session, IDENTITY_ACTIONS[2], user_id, {
        "assignment_id": assignment.id, "active": True,
    }, {
        "assignment_id": assignment.id, "active": False,
        "revoked_at": revoked_at.isoformat(), "revoked_by": evidence.actor_id,
    }, evidence, assignment.department_id)
    return assignment


def update_organization_profile(session, user_id, values, *, expected_revision, evidence):
    """Unit 7 extension: audited profile changes participate in identity revisions.

    Existing fingerprint format is unchanged; new audit IDs detect cooperating
    profile writers without invalidating pre-existing reviewed manifests upfront.
    Caller authorizes scope, validates inputs and locks referenced departments.
    """
    if not values or set(values) - {"name", "email", "department_id"}:
        raise IdentityError("Only explicit profile fields may be changed")
    if any(not isinstance(value, str) or not value.strip() for value in values.values()):
        raise IdentityError("Profile values must be nonempty strings")
    _prepare(session, user_id, expected_revision, evidence)
    user = session.query(User).filter_by(id=user_id).populate_existing().one()
    changed = {key: value for key, value in values.items() if getattr(user, key) != value}
    if not changed:
        return None
    previous = {key: getattr(user, key) for key in changed}
    for key, value in changed.items():
        setattr(user, key, value)
    return _audit(session, "ORGANIZATION_PROFILE_CHANGED", user_id, previous, changed, evidence)


def set_organization_account_active(session, user_id, active, *, expected_revision, evidence):
    if type(active) is not bool:
        raise IdentityError("Explicit account lifecycle state required")
    _prepare(session, user_id, expected_revision, evidence)
    user = session.query(User).filter_by(id=user_id).populate_existing().one()
    if user.active == active:
        return None
    previous = user.active
    user.active = active
    return _audit(session, "ORGANIZATION_ACCOUNT_STATUS_CHANGED", user_id, previous, active, evidence)


def record_organization_employee_created(session, user_id, *, expected_revision, evidence):
    """Strict creation evidence after the caller has inserted an inactive identity."""
    _prepare(session, user_id, expected_revision, evidence)
    user = session.query(User).filter_by(id=user_id).populate_existing().one()
    if user.active or user.organization_role is not OrganizationRole.EMPLOYEE:
        raise IdentityError("New employee creation must remain inactive and canonical EMPLOYEE")
    return _audit(session, "ORGANIZATION_EMPLOYEE_CREATED", user_id, None,
                  {"organization_role": OrganizationRole.EMPLOYEE.value,
                   "active": False, "home_department_id": user.department_id}, evidence)
