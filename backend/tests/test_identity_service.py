from datetime import datetime, timezone
import json

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.core.constants import OrganizationRole
from app.models import AccessGrant, AccessRequest, AuditEvent, Base, Department, DepartmentAdminAssignment, Resource, User
from app.services.identity_service import (
    IdentityError, IdentityEvidence, StaleIdentityError, change_organization_role,
    create_department_admin_assignment, read_identity_state, revoke_department_admin_assignment,
)


@pytest.fixture
def engine():
    disposable = create_engine("sqlite:///:memory:", poolclass=StaticPool,
                               connect_args={"check_same_thread": False})

    @event.listens_for(disposable, "connect")
    def foreign_keys(connection, record):
        connection.execute("PRAGMA foreign_keys=ON")

    # Explicit nullable pre-0010 transition fixture; final-schema tests are separate.
    from tests.identity_transition_support import create_transition_schema
    create_transition_schema(disposable)
    yield disposable
    disposable.dispose()


@pytest.fixture
def identity_data(engine):
    ids = {name: f"fictional-{name}" for name in ("operator", "reviewer", "target", "inactive", "hr", "finance")}
    with Session(engine) as session:
        session.add_all([Department(id=ids[name], name=name) for name in ("hr", "finance")])
        session.flush()
        session.add_all([User(
            id=ids[name], name=name, email=f"{name}@example.invalid",
            password_hash="DO_NOT_AUDIT_HASH", role="ADMIN" if name == "operator" else "EMPLOYEE",
            department_id=ids["hr"], active=name != "inactive",
        ) for name in ("operator", "reviewer", "target", "inactive")])
        session.flush()
        resource = Resource(id="fictional-resource", name="Existing", department_id=ids["finance"],
                            owner_id=ids["target"], sensitivity="CRITICAL")
        session.add(resource)
        session.flush()
        request = AccessRequest(id="fictional-request", requester_id=ids["target"], resource_id=resource.id,
                                permission="read", reason="Existing reason", status="APPROVED")
        session.add(request)
        session.flush()
        session.add_all([
            AccessGrant(id="fictional-grant", user_id=ids["target"], resource_id=resource.id,
                        permission="read", access_request_id=request.id, granted_by=ids["operator"]),
            AuditEvent(id="fictional-history", action="LEGACY_EVENT", outcome="ALLOW",
                       actor_id=ids["operator"], resource_id=resource.id, context_data={"evidence": "keep"}),
        ])
        session.commit()
    return ids


def revision(engine, user_id):
    with Session(engine) as session:
        return read_identity_state(session, user_id).revision


def set_role(engine, ids, role):
    expected = revision(engine, ids["target"])
    with Session(engine) as session, session.begin():
        change_organization_role(session, ids["target"], role, expected_revision=expected,
                                 evidence=IdentityEvidence(ids["operator"], "Reviewed identity change"))


def create_assignment(engine, ids, department="hr"):
    expected = revision(engine, ids["target"])
    with Session(engine) as session, session.begin():
        assignment = create_department_admin_assignment(
            session, ids["target"], ids[department], expected_revision=expected,
            evidence=IdentityEvidence(ids["operator"], "Reviewed assignment"),
        )
        return assignment.id


def test_role_and_audit_commit_together_without_changing_legacy(engine, identity_data):
    ids = identity_data
    set_role(engine, ids, OrganizationRole.DEPARTMENT_ADMIN)
    with Session(engine) as session:
        user = session.get(User, ids["target"])
        audit = session.scalar(select(AuditEvent).where(AuditEvent.action == "ORGANIZATION_ROLE_CHANGED"))
        assert user.organization_role is OrganizationRole.DEPARTMENT_ADMIN
        assert user.role == "EMPLOYEE" and user.password_hash == "DO_NOT_AUDIT_HASH"
        assert audit.actor_id == ids["operator"]
        assert audit.context_data["target_user_id"] == ids["target"]
        assert audit.context_data["previous_value"] is None
        assert audit.context_data["new_value"] == "DEPARTMENT_ADMIN"
        assert audit.context_data["department_id"] is None
        assert audit.context_data["reason"] == "Reviewed identity change"
        assert datetime.fromisoformat(audit.context_data["changed_at"]).tzinfo == timezone.utc
        assert "DO_NOT_AUDIT_HASH" not in json.dumps(audit.context_data)


@pytest.mark.parametrize("operation", ["role", "assign", "revoke"])
def test_audit_persistence_failure_rolls_back_each_identity_mutation(engine, identity_data, operation):
    ids = identity_data
    if operation != "role":
        set_role(engine, ids, OrganizationRole.DEPARTMENT_ADMIN)
    assignment_id = create_assignment(engine, ids) if operation == "revoke" else None
    before = revision(engine, ids["target"])
    attempts = []

    def fail_audit(mapper, connection, audit):
        attempts.append(audit.action)
        raise RuntimeError("Injected identity audit failure")

    event.listen(AuditEvent, "before_insert", fail_audit)
    try:
        with pytest.raises(RuntimeError, match="identity audit failure"):
            with Session(engine) as session, session.begin():
                kwargs = {"expected_revision": before, "evidence": IdentityEvidence(ids["operator"], "Test failure")}
                if operation == "role":
                    change_organization_role(session, ids["target"], OrganizationRole.EMPLOYEE, **kwargs)
                elif operation == "assign":
                    create_department_admin_assignment(session, ids["target"], ids["hr"], **kwargs)
                else:
                    revoke_department_admin_assignment(session, ids["target"], assignment_id, **kwargs)
    finally:
        event.remove(AuditEvent, "before_insert", fail_audit)
    assert len(attempts) == 1
    assert revision(engine, ids["target"]) == before


def test_assignment_and_revocation_match_audit_and_preserve_period(engine, identity_data):
    ids = identity_data
    set_role(engine, ids, OrganizationRole.DEPARTMENT_ADMIN)
    assignment_id = create_assignment(engine, ids)
    before = revision(engine, ids["target"])
    with Session(engine) as session, session.begin():
        revoke_department_admin_assignment(session, ids["target"], assignment_id, expected_revision=before,
                                           evidence=IdentityEvidence(ids["operator"], "Assignment ended"))
    with Session(engine) as session:
        assignment = session.get(DepartmentAdminAssignment, assignment_id)
        assert assignment.assigned_by == assignment.revoked_by == ids["operator"]
        assert assignment.revoked_at is not None
        audits = session.scalars(select(AuditEvent).where(AuditEvent.action.like("DEPARTMENT_ADMIN_%"))).all()
        assert {a.action for a in audits} == {"DEPARTMENT_ADMIN_ASSIGNED", "DEPARTMENT_ADMIN_REVOKED"}
        for audit in audits:
            assert audit.context_data["department_id"] == ids["hr"]
            assert audit.context_data["target_user_id"] == ids["target"]
            assert audit.context_data["new_value"]["assignment_id"] == assignment_id


def test_stale_revision_detects_role_aba_and_preserves_newer_state(engine, identity_data):
    ids = identity_data
    set_role(engine, ids, OrganizationRole.EMPLOYEE)
    old = revision(engine, ids["target"])
    set_role(engine, ids, OrganizationRole.DEPARTMENT_ADMIN)
    set_role(engine, ids, OrganizationRole.EMPLOYEE)
    current = revision(engine, ids["target"])
    with pytest.raises(StaleIdentityError):
        with Session(engine) as session, session.begin():
            change_organization_role(session, ids["target"], OrganizationRole.SUPER_ADMIN,
                                     expected_revision=old, evidence=IdentityEvidence(ids["operator"], "Stale"))
    assert revision(engine, ids["target"]) == current


def test_stale_assignment_plan_cannot_silently_add_another_assignment(engine, identity_data):
    ids = identity_data
    set_role(engine, ids, OrganizationRole.DEPARTMENT_ADMIN)
    old = revision(engine, ids["target"])
    create_assignment(engine, ids)
    with pytest.raises(StaleIdentityError):
        with Session(engine) as session, session.begin():
            create_department_admin_assignment(session, ids["target"], ids["finance"],
                expected_revision=old, evidence=IdentityEvidence(ids["operator"], "Stale"))
    with Session(engine) as session:
        assert len(session.scalars(select(DepartmentAdminAssignment)).all()) == 1


def test_batch_failure_rolls_back_prior_successful_primitives(engine, identity_data):
    ids = identity_data
    before = revision(engine, ids["target"])
    with pytest.raises(IdentityError, match="Unknown department"):
        with Session(engine) as session, session.begin():
            evidence = IdentityEvidence(ids["operator"], "Batch")
            change_organization_role(session, ids["target"], OrganizationRole.DEPARTMENT_ADMIN,
                                     expected_revision=before, evidence=evidence)
            create_department_admin_assignment(session, ids["target"], "missing",
                expected_revision=read_identity_state(session, ids["target"]).revision, evidence=evidence)
    assert revision(engine, ids["target"]) == before


def test_explicit_transaction_required(engine, identity_data):
    ids = identity_data
    with Session(engine) as session, pytest.raises(IdentityError, match="explicit session.begin"):
        change_organization_role(session, ids["target"], OrganizationRole.EMPLOYEE,
            expected_revision=revision(engine, ids["target"]), evidence=IdentityEvidence(ids["operator"], "Test"))


def test_role_demotion_requires_explicit_assignment_revocation(engine, identity_data):
    ids = identity_data
    set_role(engine, ids, OrganizationRole.DEPARTMENT_ADMIN)
    create_assignment(engine, ids)
    before = revision(engine, ids["target"])
    with pytest.raises(IdentityError, match="Revoke active"):
        with Session(engine) as session, session.begin():
            change_organization_role(session, ids["target"], OrganizationRole.EMPLOYEE,
                expected_revision=before, evidence=IdentityEvidence(ids["operator"], "Demotion"))
    assert revision(engine, ids["target"]) == before


def test_repeated_assignment_operations_are_noops_after_fresh_review(engine, identity_data):
    ids = identity_data
    set_role(engine, ids, OrganizationRole.DEPARTMENT_ADMIN)
    assignment_id = create_assignment(engine, ids)
    before = revision(engine, ids["target"])
    assert create_assignment(engine, ids) == assignment_id
    assert revision(engine, ids["target"]) == before


def test_unsupported_provenance_fields_are_rejected():
    with pytest.raises(IdentityError, match="Unsupported audit"):
        IdentityEvidence("actor", "Reason", {"password": "must-not-be-recorded"})


def test_evidence_copies_and_freezes_allowlisted_provenance():
    provenance = {"approval_reference": "FICTIONAL-reference"}
    evidence = IdentityEvidence("actor", "Reason", provenance)
    provenance["password"] = "must-not-be-recorded"
    assert "password" not in evidence.provenance
    with pytest.raises(TypeError):
        evidence.provenance["password"] = "must-not-be-recorded"
