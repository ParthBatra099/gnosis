"""Organization administration only; no authentication or business-data grants."""
from contextlib import contextmanager
import hashlib
import json
import secrets

from fastapi import HTTPException
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.constants import OrganizationRole
from app.core.security import hash_password
from app.models import AuditEvent, Department, DepartmentAdminAssignment, MFACredential, Resource, User
from app.schemas.organization import DepartmentRead, EmployeeRead, AssignmentRead
from app.services import organization_authority as authority
from app.services import identity_service as identity
from app.services.authentication_sessions import invalidate_user_sessions

A = authority.AdministrativeAction
DEPARTMENT_EVENTS = ("ORGANIZATION_DEPARTMENT_CREATED", "ORGANIZATION_DEPARTMENT_UPDATED", "ORGANIZATION_DEPARTMENT_STATUS")


def error(status, code):
    raise HTTPException(status, {"code": code})


def require(decision):
    if not decision.allowed:
        error(403, decision.reason.value)


@contextmanager
def mutation(source, actor_id, action):
    """A normal explicit transaction on the existing bind, with current policy.

    Low-frequency organization writes lock existing identities in stable ID order
    before actor/target locks. Shared immutable user history makes this a common
    serialization point for last-admin and normalized-identity invariants. No
    separate engine or transaction framework. DB errors roll back and fail closed.
    """
    with Session(bind=source.get_bind(), autoflush=False, expire_on_commit=False) as db, db.begin():
        require(authority.evaluate_authority(db, actor_id, action, authority.OrganizationScope()))
        db.execute(select(User.id).order_by(User.id).with_for_update()).all()
        require(authority.revalidate_authority_for_mutation(db, actor_id, action, authority.OrganizationScope()))
        yield db


def read_scope(db, actor_id, global_action):
    global_access = authority.evaluate_authority(db, actor_id, global_action, authority.OrganizationScope()).allowed
    if global_access:
        return True, ()
    ids = tuple(identifier for identifier in db.scalars(select(Department.id)) if authority.evaluate_authority(
        db, actor_id, A.DEPARTMENT_ADMINISTER, authority.DepartmentScope(identifier)).allowed)
    if not ids:
        error(403, "ADMINISTRATIVE_SCOPE_REQUIRED")
    return False, ids


def department_revision(db, department):
    events = db.scalars(select(AuditEvent.id).where(AuditEvent.action.in_(DEPARTMENT_EVENTS),
        AuditEvent.context_data["department_id"].as_string() == department.id).order_by(AuditEvent.id)).all()
    payload = [department.id, department.name, department.description, department.active, events]
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def department_read(db, department):
    return DepartmentRead(id=department.id, name=department.name, description=department.description,
                          active=department.active, revision=department_revision(db, department))


def employee_read(db, user):
    return EmployeeRead(id=user.id, name=user.name, email=user.email, organization_role=user.organization_role,
        home_department_id=user.department_id, active=user.active, revision=identity.read_identity_state(db, user.id).revision)


def assignment_read(db, assignment):
    return AssignmentRead(id=assignment.id, user_id=assignment.user_id, department_id=assignment.department_id,
        assigned_at=assignment.assigned_at, assigned_by=assignment.assigned_by, revoked_at=assignment.revoked_at,
        revoked_by=assignment.revoked_by, revision=identity.read_identity_state(db, assignment.user_id).revision)


def departments_query(db, actor_id):
    global_access, ids = read_scope(db, actor_id, A.ORGANIZATION_ADMINISTER)
    query = db.query(Department)
    return query if global_access else query.filter(Department.id.in_(ids))


def employees_query(db, actor_id):
    global_access, ids = read_scope(db, actor_id, A.IDENTITY_ADMINISTER)
    query = db.query(User)
    return query if global_access else query.filter(User.department_id.in_(ids))


def department_target(db, actor_id, department_id):
    department = departments_query(db, actor_id).filter(Department.id == department_id).populate_existing().first()
    if department is None:
        error(404, "NOT_FOUND")
    return department


def employee_target(db, actor_id, user_id):
    user = employees_query(db, actor_id).filter(User.id == user_id).populate_existing().first()
    if user is None:
        error(404, "NOT_FOUND")
    return user


def lock_department(db, department_id, *, active=False):
    department = db.query(Department).filter_by(id=department_id).with_for_update().populate_existing().first()
    if department is None:
        error(404, "NOT_FOUND")
    if active and not department.active:
        error(409, "DEPARTMENT_INACTIVE")
    return department


def lock_user(db, user_id, expected_revision):
    if db.scalar(select(User.id).where(User.id == user_id)) is None:
        error(404, "NOT_FOUND")
    state = identity.lock_identity(db, user_id)
    if state.revision != expected_revision:
        raise identity.StaleIdentityError("Identity changed since review")
    return db.query(User).filter_by(id=user_id).populate_existing().one()


def strict_audit(db, actor_id, action, reason, *, department_id=None, previous=None, new=None):
    db.add(AuditEvent(actor_id=actor_id, action=action, outcome="ALLOW", reason="ORGANIZATION_CHANGE",
        context_data={"department_id": department_id, "previous_value": previous, "new_value": new, "reason": reason}))
    db.flush()


def check_department_revision(db, department, expected):
    if department_revision(db, department) != expected:
        error(409, "STALE_REVISION")


def create_department(db, actor_id, payload):
    if db.scalar(select(Department.id).where(func.lower(func.trim(Department.name)) == func.lower(payload.name))) is not None:
        error(409, "DUPLICATE_DEPARTMENT")
    department = Department(name=payload.name, description=payload.description, active=True)
    db.add(department); db.flush()
    strict_audit(db, actor_id, DEPARTMENT_EVENTS[0], payload.reason, department_id=department.id,
                 new={"name": department.name, "description": department.description, "active": True})
    return department_read(db, department)


def update_department(db, actor_id, department_id, payload):
    department = lock_department(db, department_id)
    check_department_revision(db, department, payload.expected_revision)
    if payload.name is not None and db.scalar(select(Department.id).where(Department.id != department_id,
            func.lower(func.trim(Department.name)) == func.lower(payload.name))) is not None:
        error(409, "DUPLICATE_DEPARTMENT")
    previous = {"name": department.name, "description": department.description}
    for field in payload.model_fields_set.intersection({"name", "description"}):
        setattr(department, field, getattr(payload, field))
    strict_audit(db, actor_id, DEPARTMENT_EVENTS[1], payload.reason, department_id=department_id,
                 previous=previous, new={"name": department.name, "description": department.description})
    return department_read(db, department)


def department_status(db, actor_id, department_id, payload, active):
    department = lock_department(db, department_id)
    check_department_revision(db, department, payload.expected_revision)
    if not active:
        if (db.scalar(select(User.id).where(User.department_id == department_id, User.active.is_(True)).limit(1))
                or db.scalar(select(Resource.id).where(Resource.department_id == department_id).limit(1))
                or db.scalar(select(DepartmentAdminAssignment.id).where(DepartmentAdminAssignment.department_id == department_id,
                    DepartmentAdminAssignment.revoked_at.is_(None)).limit(1))):
            error(409, "DEPARTMENT_HAS_LIVE_REFERENCES")
    if department.active != active:
        previous = department.active
        department.active = active
        strict_audit(db, actor_id, DEPARTMENT_EVENTS[2], payload.reason, department_id=department_id,
                     previous=previous, new=active)
    return department_read(db, department)


def evidence(actor_id, payload):
    return identity.IdentityEvidence(actor_id, payload.reason)


def create_employee(db, actor_id, payload):
    lock_department(db, payload.home_department_id, active=True)
    email = str(payload.email).lower()
    if db.scalar(select(User.id).where(func.lower(User.email) == email)):
        error(409, "DUPLICATE_EMPLOYEE")
    # Unrecoverable/discarded random password: this is an inactive identity, not a
    # usable credential or enrollment grant. No secret is returned or delivered.
    user = User(name=payload.name, email=email, password_hash=hash_password(secrets.token_urlsafe(48)),
                role="EMPLOYEE", organization_role=OrganizationRole.EMPLOYEE, department_id=payload.home_department_id, active=False)
    db.add(user); db.flush()
    expected = identity.read_identity_state(db, user.id).revision
    identity.change_organization_role(db, user.id, OrganizationRole.EMPLOYEE, expected_revision=expected, evidence=evidence(actor_id, payload))
    identity.record_organization_employee_created(db, user.id,
        expected_revision=identity.read_identity_state(db, user.id).revision, evidence=evidence(actor_id, payload))
    return employee_read(db, user)


def update_employee(db, actor_id, user_id, payload):
    user = lock_user(db, user_id, payload.expected_revision)
    fields = payload.model_fields_set.intersection({"name", "email", "home_department_id"})
    values = {key: str(getattr(payload, key)) for key in fields}
    if "home_department_id" in values:
        if user_id == actor_id and values["home_department_id"] != user.department_id:
            error(403, "SELF_SCOPE_CHANGE_PROHIBITED")
        lock_department(db, values["home_department_id"], active=True)
        values["department_id"] = values.pop("home_department_id")
    if "email" in values:
        values["email"] = values["email"].lower()
        if db.scalar(select(User.id).where(User.id != user_id, func.lower(User.email) == values["email"])):
            error(409, "DUPLICATE_EMPLOYEE")
    sensitive = any(key in values and getattr(user, key) != values[key] for key in ("email", "department_id"))
    event = identity.update_organization_profile(db, user_id, values, expected_revision=payload.expected_revision, evidence=evidence(actor_id, payload))
    if event is not None and sensitive:
        invalidate_user_sessions(db, user_id, actor_user_id=actor_id, reason="SECURITY_CHANGE")
    return employee_read(db, db.query(User).filter_by(id=user_id).populate_existing().one())


def protect_last_admin(db, user):
    if user.active and user.organization_role is OrganizationRole.SUPER_ADMIN:
        remaining = db.query(User.id).join(MFACredential, MFACredential.user_id == User.id).filter(
            User.active.is_(True), User.organization_role == OrganizationRole.SUPER_ADMIN, User.id != user.id,
            MFACredential.status == "ACTIVE", MFACredential.revoked_at.is_(None)).distinct().count()
        if remaining == 0:
            error(409, "LAST_SUPER_ADMIN_PROTECTED")


def change_role(db, actor_id, user_id, payload):
    user = lock_user(db, user_id, payload.expected_revision)
    if payload.organization_role != user.organization_role:
        protect_last_admin(db, user)
    event = identity.change_organization_role(db, user_id, payload.organization_role,
        expected_revision=payload.expected_revision, evidence=evidence(actor_id, payload))
    if event is not None:
        invalidate_user_sessions(db, user_id, actor_user_id=actor_id, reason="SECURITY_CHANGE")
    return employee_read(db, db.query(User).filter_by(id=user_id).populate_existing().one())


def employee_status(db, actor_id, user_id, payload, active):
    user = lock_user(db, user_id, payload.expected_revision)
    if not active:
        protect_last_admin(db, user)
    elif not user.active:
        lock_department(db, user.department_id, active=True)
        if db.scalar(select(MFACredential.id).where(MFACredential.user_id == user_id, MFACredential.status == "ACTIVE")) is None:
            error(409, "TRUSTED_ACCOUNT_SETUP_REQUIRED")
    event = identity.set_organization_account_active(db, user_id, active,
        expected_revision=payload.expected_revision, evidence=evidence(actor_id, payload))
    if event is not None:
        invalidate_user_sessions(db, user_id, actor_user_id=actor_id, reason="SECURITY_CHANGE")
    return employee_read(db, db.query(User).filter_by(id=user_id).populate_existing().one())


def create_assignment(db, actor_id, payload):
    if payload.user_id == actor_id:
        error(403, "SELF_ASSIGNMENT_PROHIBITED")
    lock_user(db, payload.user_id, payload.expected_revision)
    lock_department(db, payload.department_id, active=True)
    if db.scalar(select(DepartmentAdminAssignment.id).where(DepartmentAdminAssignment.user_id == payload.user_id,
            DepartmentAdminAssignment.department_id == payload.department_id, DepartmentAdminAssignment.revoked_at.is_(None))):
        error(409, "DUPLICATE_ACTIVE_ASSIGNMENT")
    assignment = identity.create_department_admin_assignment(db, payload.user_id, payload.department_id,
        expected_revision=payload.expected_revision, evidence=evidence(actor_id, payload))
    invalidate_user_sessions(db, payload.user_id, actor_user_id=actor_id, reason="SECURITY_CHANGE")
    return assignment_read(db, assignment)


def revoke_assignment(db, actor_id, assignment_id, payload):
    assignment = db.query(DepartmentAdminAssignment).filter_by(id=assignment_id).first()
    if assignment is None:
        error(404, "NOT_FOUND")
    lock_user(db, assignment.user_id, payload.expected_revision)
    lock_department(db, assignment.department_id)
    assignment = db.query(DepartmentAdminAssignment).filter_by(id=assignment_id).with_for_update().populate_existing().one()
    if assignment.revoked_at is not None:
        error(409, "ASSIGNMENT_ALREADY_REVOKED")
    identity.revoke_department_admin_assignment(db, assignment.user_id, assignment.id,
        expected_revision=payload.expected_revision, evidence=evidence(actor_id, payload))
    invalidate_user_sessions(db, assignment.user_id, actor_user_id=actor_id, reason="SECURITY_CHANGE")
    return assignment_read(db, assignment)
