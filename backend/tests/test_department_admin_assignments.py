"""Unit 1 storage tests; no authentication or authorization is introduced here."""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.orm import Session

from app.core.constants import OrganizationRole
from app.models import (
    AccessGrant, AccessRequest, AuditEvent, Base, Department,
    DepartmentAdminAssignment, Resource, User,
)


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, record):
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    # Explicit nullable pre-0010 transition fixture; final-schema tests are separate.
    from tests.identity_transition_support import create_transition_schema
    create_transition_schema(engine)
    try:
        with Session(engine) as session:
            yield session
    finally:
        engine.dispose()


@pytest.fixture
def identities(db):
    home, hr, finance = [Department(name=name) for name in ("Home", "HR", "Finance")]
    db.add_all([home, hr, finance])
    db.flush()
    actor = User(name="Reviewer", email="reviewer@example.com", password_hash="unused",
                 role="ADMIN", organization_role=OrganizationRole.SUPER_ADMIN, department_id=home.id)
    first = User(name="First", email="first@example.com", password_hash="unused",
                 role="MANAGER", organization_role=OrganizationRole.DEPARTMENT_ADMIN,
                 department_id=home.id)
    second = User(name="Second", email="second@example.com", password_hash="unused",
                  role="EMPLOYEE", organization_role=OrganizationRole.DEPARTMENT_ADMIN,
                  department_id=home.id)
    db.add_all([actor, first, second])
    db.commit()
    return actor, first, second, home, hr, finance


def assign(user, department, actor, **kwargs):
    return DepartmentAdminAssignment(user_id=user.id, department_id=department.id,
                                     assigned_by=actor.id, **kwargs)


@pytest.mark.parametrize("role", list(OrganizationRole))
def test_each_canonical_role_round_trips_without_changing_legacy_role(db, role):
    department = Department(name="Home")
    user = User(name="Legacy", email="legacy@example.com", password_hash="unchanged",
                role="ADMIN", organization_role=role, department=department)
    db.add(user)
    db.commit()
    user_id = user.id
    db.expire_all()
    saved = db.get(User, user_id)
    assert saved.organization_role is role
    assert saved.role == "ADMIN"
    assert saved.password_hash == "unchanged"


@pytest.mark.parametrize("legacy", ["ADMIN", "MANAGER", "SECURITY_OFFICER", "EMPLOYEE"])
def test_unmapped_legacy_roles_have_no_canonical_default_or_fallback(db, legacy):
    user = User(name="Unmapped", email="unmapped@example.com", password_hash="unused",
                role=legacy, department=Department(name="Home"))
    db.add(user)
    db.commit()
    db.refresh(user)
    assert user.organization_role is None
    assert user.role == legacy
    assert User.__table__.c.organization_role.default is None
    assert User.__table__.c.organization_role.server_default is None


@pytest.mark.parametrize("role", ["ADMIN", "MANAGER", "super_admin", "", "SECURITY_OFFICER"])
def test_invalid_canonical_roles_rejected_by_orm(db, role):
    db.add(User(name="Invalid", email="invalid@example.com", password_hash="unused",
                organization_role=role, department=Department(name="Home")))
    with pytest.raises(StatementError):
        db.commit()
    db.rollback()


def test_database_rejects_invalid_role_when_orm_validation_is_bypassed(db, identities):
    actor = identities[0]
    with pytest.raises(IntegrityError, match="ck_users_organization_role"):
        db.execute(text("UPDATE users SET organization_role = 'ADMIN' WHERE id = :id"), {"id": actor.id})
    db.rollback()
    assert db.get(User, actor.id).organization_role is OrganizationRole.SUPER_ADMIN


def test_multiple_admins_can_administer_one_department(db, identities):
    actor, first, second, home, hr, finance = identities
    db.add_all([assign(first, hr, actor), assign(second, hr, actor)])
    db.commit()
    db.expire_all()
    assert {a.user_id for a in hr.admin_assignments} == {first.id, second.id}
    assert first.department_id == second.department_id == home.id


def test_one_admin_can_administer_multiple_departments(db, identities):
    actor, first, second, home, hr, finance = identities
    db.add_all([assign(first, hr, actor), assign(first, finance, actor)])
    db.commit()
    db.expire_all()
    assert {a.department_id for a in first.department_admin_assignments} == {hr.id, finance.id}
    assert first.department_id == home.id


def test_duplicate_active_pair_is_rejected_by_database(db, identities):
    actor, first, second, home, hr, finance = identities
    original = assign(first, hr, actor)
    db.add(original)
    db.commit()
    original_id = original.id
    db.add(assign(first, hr, actor))
    with pytest.raises(IntegrityError, match="UNIQUE"):
        db.commit()
    db.rollback()
    assert db.query(DepartmentAdminAssignment).one().id == original_id


def test_revocation_and_reassignment_preserve_each_period_and_actor(db, identities):
    actor, first, second, home, hr, finance = identities
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    original = assign(first, hr, actor, assigned_at=now)
    db.add(original)
    db.commit()
    original_id = original.id
    actor_id = actor.id
    original.revoked_at = now + timedelta(days=1)
    original.revoked_by = actor_id
    db.commit()
    replacement = assign(first, hr, actor, assigned_at=now + timedelta(days=2))
    db.add(replacement)
    db.commit()
    replacement.revoked_at = now + timedelta(days=3)
    replacement.revoked_by = actor_id
    db.commit()
    current = assign(first, hr, actor, assigned_at=now + timedelta(days=4))
    db.add(current)
    db.commit()
    db.expire_all()
    history = db.query(DepartmentAdminAssignment).order_by(DepartmentAdminAssignment.assigned_at).all()
    assert len(history) == 3
    assert history[0].id == original_id
    assert history[0].assigned_by_user.id == actor.id
    assert history[0].revoked_by_user.id == actor.id
    assert [a.revoked_at is None for a in history] == [False, False, True]
    assert {a.id for a in first.department_admin_assignments} == {a.id for a in history}


@pytest.mark.parametrize("bad_state", ["missing_actor", "missing_timestamp", "before_assignment"])
def test_invalid_revocation_state_is_rejected(db, identities, bad_state):
    actor, first, second, home, hr, finance = identities
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    assignment = assign(first, hr, actor, assigned_at=now)
    if bad_state != "missing_timestamp":
        assignment.revoked_at = now - timedelta(days=1) if bad_state == "before_assignment" else now
    if bad_state != "missing_actor":
        assignment.revoked_by = actor.id
    db.add(assignment)
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


@pytest.mark.parametrize("field", ["user_id", "department_id", "assigned_by", "revoked_by"])
def test_assignment_foreign_keys_reject_missing_references(db, identities, field):
    actor, first, second, home, hr, finance = identities
    assignment = assign(first, hr, actor)
    if field == "revoked_by":
        assignment.revoked_at = datetime.now(timezone.utc) + timedelta(days=1)
    setattr(assignment, field, "does-not-exist")
    db.add(assignment)
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


def test_assignments_do_not_change_existing_identity_or_governance(db, identities):
    actor, owner, requester, home, hr, finance = identities
    owner.organization_role = None
    resource = Resource(name="Existing resource", department_id=hr.id, owner_id=owner.id,
                        sensitivity="CRITICAL")
    db.add(resource)
    db.flush()
    request = AccessRequest(requester_id=requester.id, resource_id=resource.id,
                            permission="read", reason="Existing justification", status="APPROVED")
    db.add(request)
    db.flush()
    grant = AccessGrant(user_id=requester.id, resource_id=resource.id, permission="read",
                        access_request_id=request.id, granted_by=owner.id)
    audit = AuditEvent(actor_id=owner.id, resource_id=resource.id, action="EXISTING_EVENT",
                       outcome="ALLOW", context_data={"evidence": "unchanged"})
    db.add_all([grant, audit])
    db.commit()
    original_ids = (owner.id, requester.id, resource.id, request.id, grant.id, audit.id)
    db.add(assign(owner, finance, actor))
    db.commit()
    db.expire_all()
    assert original_ids == (owner.id, requester.id, resource.id, request.id, grant.id, audit.id)
    assert owner.role == "MANAGER" and owner.organization_role is None
    assert owner.department.id == home.id
    assert resource.owner.id == owner.id and resource.department.id == hr.id
    assert resource in owner.owned_resources and resource in hr.resources
    assert request.requester.id == requester.id and request.reason == "Existing justification"
    assert grant.access_request.id == request.id and grant.granter.id == owner.id
    assert audit.context_data == {"evidence": "unchanged"}


def test_deleting_assignment_actor_cannot_erase_provenance(db, identities):
    actor, first, second, home, hr, finance = identities
    assignment = assign(first, hr, actor)
    db.add(assignment)
    db.commit()
    actor_id, assignment_id = actor.id, assignment.id
    db.delete(actor)
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()
    assert db.get(User, actor_id) is not None
    assert db.get(DepartmentAdminAssignment, assignment_id).assigned_by == actor_id
