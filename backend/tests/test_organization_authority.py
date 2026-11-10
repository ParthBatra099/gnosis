from dataclasses import FrozenInstanceError, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import event, select, text, update
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session

from app.core.constants import OrganizationRole
from app.models import AccessRequest, AuditEvent, Department, DepartmentAdminAssignment, Incident, Resource, User
from app.security.access_decision import evaluate_access
from app.services import organization_authority as authority
from app.services.identity_service import (
    IdentityEvidence, change_organization_role, read_identity_state, revoke_department_admin_assignment,
)
from app.services.organization_authority import (
    ACTION_MATRIX, AccessRequestScope, AdministrativeAction as Action, AuthorityReason as Reason,
    DepartmentScope, OrganizationScope, ScopeKind, evaluate_authority, revalidate_authority_for_mutation,
)
from tests.test_identity_service import engine, identity_data


GLOBAL_ACTIONS = {
    Action.ORGANIZATION_ADMINISTER, Action.IDENTITY_ADMINISTER,
    Action.DEPARTMENT_ASSIGNMENTS_ADMINISTER, Action.ORGANIZATION_SECURITY_MONITOR,
}
REQUEST_ACTIONS = {Action.ACCESS_REQUEST_APPROVE, Action.ACCESS_REQUEST_REJECT}


@pytest.fixture
def actors(engine, identity_data):
    ids = identity_data
    with Session(engine) as session, session.begin():
        for name, role in (("operator", OrganizationRole.SUPER_ADMIN),
                           ("reviewer", OrganizationRole.DEPARTMENT_ADMIN),
                           ("target", OrganizationRole.EMPLOYEE), ("inactive", OrganizationRole.SUPER_ADMIN)):
            session.get(User, ids[name]).organization_role = role
        assignment = DepartmentAdminAssignment(user_id=ids["reviewer"], department_id=ids["finance"],
            assigned_by=ids["operator"], assigned_at=datetime.now(timezone.utc) - timedelta(days=1))
        session.add(assignment)
        session.flush()
        assignment_id = assignment.id
    return {**ids, "assignment": assignment_id,
            OrganizationRole.SUPER_ADMIN: ids["operator"], OrganizationRole.DEPARTMENT_ADMIN: ids["reviewer"],
            OrganizationRole.EMPLOYEE: ids["target"]}


def scope_for(action, actors):
    if action in GLOBAL_ACTIONS:
        return OrganizationScope()
    if action in REQUEST_ACTIONS:
        return AccessRequestScope("fictional-request", actors["finance"])
    return DepartmentScope(actors["finance"])


@pytest.mark.parametrize("role", list(OrganizationRole))
@pytest.mark.parametrize("action", list(Action))
def test_every_canonical_role_against_every_administrative_action(engine, actors, role, action):
    expected = role is OrganizationRole.SUPER_ADMIN or (
        role is OrganizationRole.DEPARTMENT_ADMIN and action not in GLOBAL_ACTIONS)
    with Session(engine) as session:
        decision = evaluate_authority(session, actors[role], action, scope_for(action, actors))
    assert decision.allowed is expected
    assert decision.actor_user_id == actors[role] and decision.action is action
    assert decision.explanation
    if expected:
        assert decision.reason is (Reason.ALLOW_SUPER_ADMIN if role is OrganizationRole.SUPER_ADMIN
                                   else Reason.ALLOW_DEPARTMENT_ASSIGNMENT)


def test_action_matrix_is_complete_explicit_and_immutable():
    assert set(ACTION_MATRIX) == set(Action)
    for action, policy in ACTION_MATRIX.items():
        assert policy.permitted_roles == (frozenset({OrganizationRole.SUPER_ADMIN}) if action in GLOBAL_ACTIONS
            else frozenset({OrganizationRole.SUPER_ADMIN, OrganizationRole.DEPARTMENT_ADMIN}))
        assert policy.scope_kind is (ScopeKind.ORGANIZATION if action in GLOBAL_ACTIONS else
                                     ScopeKind.ACCESS_REQUEST if action in REQUEST_ACTIONS else ScopeKind.DEPARTMENT)
    with pytest.raises(TypeError):
        ACTION_MATRIX[Action.IDENTITY_ADMINISTER] = None


def test_department_admin_multiple_assignments_and_home_department_separation(engine, actors):
    action = Action.DEPARTMENT_ADMINISTER
    with Session(engine) as session:
        assert evaluate_authority(session, actors["reviewer"], action, DepartmentScope(actors["finance"])).allowed
        assert evaluate_authority(session, actors["reviewer"], action, DepartmentScope(actors["hr"])).reason is Reason.DEPARTMENT_ASSIGNMENT_REQUIRED
    with Session(engine) as session, session.begin():
        session.add(DepartmentAdminAssignment(user_id=actors["reviewer"], department_id=actors["hr"],
                                             assigned_by=actors["operator"]))
    with Session(engine) as session:
        for department in ("hr", "finance"):
            assert evaluate_authority(session, actors["reviewer"], action, DepartmentScope(actors[department])).allowed
        for organization_action in GLOBAL_ACTIONS:
            assert not evaluate_authority(session, actors["reviewer"], organization_action, OrganizationScope()).allowed
        assert session.get(User, actors["reviewer"]).department_id == actors["hr"]


def test_revocation_is_visible_despite_cached_user_and_assignment_objects(engine, actors):
    with Session(engine) as reader:
        cached_user = reader.get(User, actors["reviewer"])
        cached_assignment = cached_user.department_admin_assignments[0]
        scope = DepartmentScope(actors["finance"])
        assert evaluate_authority(reader, cached_user.id, Action.DEPARTMENT_SECURITY_MONITOR, scope).allowed
        with Session(engine) as writer, writer.begin():
            revoke_department_admin_assignment(writer, cached_user.id, actors["assignment"],
                expected_revision=read_identity_state(writer, cached_user.id).revision,
                evidence=IdentityEvidence(actors["operator"], "Reviewed revocation"))
        assert cached_assignment.revoked_at is None  # deliberately stale relationship object
        assert evaluate_authority(reader, cached_user.id, Action.DEPARTMENT_SECURITY_MONITOR, scope).reason is Reason.DEPARTMENT_ASSIGNMENT_REQUIRED


def test_demotion_is_visible_despite_cached_user(engine, actors):
    with Session(engine) as reader:
        cached = reader.get(User, actors["reviewer"])
        with Session(engine) as writer, writer.begin():
            evidence = IdentityEvidence(actors["operator"], "Reviewed demotion")
            revoke_department_admin_assignment(writer, cached.id, actors["assignment"],
                expected_revision=read_identity_state(writer, cached.id).revision, evidence=evidence)
            change_organization_role(writer, cached.id, OrganizationRole.EMPLOYEE,
                expected_revision=read_identity_state(writer, cached.id).revision, evidence=evidence)
        assert cached.organization_role is OrganizationRole.DEPARTMENT_ADMIN
        decision = evaluate_authority(reader, cached.id, Action.DEPARTMENT_ADMINISTER, DepartmentScope(actors["finance"]))
        assert decision.reason is Reason.ROLE_NOT_PERMITTED


@pytest.mark.parametrize("action", [a for a in Action if a not in GLOBAL_ACTIONS])
def test_department_admin_without_current_assignments_is_denied(engine, actors, action):
    with Session(engine) as session, session.begin():
        revoke_department_admin_assignment(session, actors["reviewer"], actors["assignment"],
            expected_revision=read_identity_state(session, actors["reviewer"]).revision,
            evidence=IdentityEvidence(actors["operator"], "End assignment"))
    with Session(engine) as session:
        decision = evaluate_authority(session, actors["reviewer"], action, scope_for(action, actors))
        assert decision.reason is Reason.DEPARTMENT_ASSIGNMENT_REQUIRED


def test_assignment_to_employee_does_not_elevate_role(engine, actors):
    with Session(engine) as session, session.begin():
        session.add(DepartmentAdminAssignment(user_id=actors["target"], department_id=actors["finance"],
                                             assigned_by=actors["operator"]))
    with Session(engine) as session:
        decision = evaluate_authority(session, actors["target"], Action.DEPARTMENT_GRANT_ADMINISTER,
                                      DepartmentScope(actors["finance"]))
        assert decision.reason is Reason.ROLE_NOT_PERMITTED and decision.assignment_evidence is None


@pytest.mark.parametrize("action", list(Action))
@pytest.mark.parametrize("role", [None, "ADMIN", "INVALID", "super_admin"])
def test_null_or_corrupt_canonical_roles_fail_closed_for_every_action(engine, actors, action, role):
    with Session(engine) as session, session.begin():
        # Only this in-memory negative fixture bypasses the Unit 1 DB check.
        session.execute(text("PRAGMA ignore_check_constraints=ON"))
        session.execute(text("UPDATE users SET organization_role=:role WHERE id=:id"),
                        {"role": role, "id": actors["operator"]})
        session.execute(text("PRAGMA ignore_check_constraints=OFF"))
    with Session(engine) as session:
        decision = evaluate_authority(session, actors["operator"], action, scope_for(action, actors))
        assert not decision.allowed
        assert decision.reason is (Reason.CANONICAL_ROLE_REQUIRED if role is None else Reason.INVALID_CANONICAL_ROLE)


@pytest.mark.parametrize("legacy", ["ADMIN", "MANAGER", "SECURITY_OFFICER", "SUPER_ADMIN", "DEPARTMENT_ADMIN", "RESOURCE_OWNER"])
def test_legacy_role_and_ownership_never_supply_administrative_authority(engine, actors, legacy):
    with Session(engine) as session, session.begin():
        user = session.get(User, actors["target"])
        user.role, user.organization_role = legacy, None
    with Session(engine) as session:
        assert session.get(Resource, "fictional-resource").owner_id == actors["target"]
        for action in (Action.IDENTITY_ADMINISTER, Action.DEPARTMENT_GRANT_ADMINISTER):
            assert evaluate_authority(session, actors["target"], action, scope_for(action, actors)).reason is Reason.CANONICAL_ROLE_REQUIRED


@pytest.mark.parametrize("actor_name", ["target", "reviewer"])
def test_incident_reporter_and_assignee_do_not_override_authority(engine, actors, actor_name):
    with Session(engine) as session, session.begin():
        # Both actors lack administration of HR, even if they report/are assigned a case.
        incident = Incident(title="Fixture", description="Fixture", severity="LOW",
                            reporter_id=actors[actor_name], assigned_to_id=actors[actor_name])
        session.add(incident)
    with Session(engine) as session:
        decision = evaluate_authority(session, actors[actor_name], Action.DEPARTMENT_INCIDENT_INVESTIGATE,
                                      DepartmentScope(actors["hr"]))
        assert not decision.allowed


@pytest.mark.parametrize("role", list(OrganizationRole))
def test_self_approval_is_prohibited_for_every_role(engine, actors, role):
    actor_id = actors[role]
    with Session(engine) as session, session.begin():
        session.add(AccessRequest(id="fictional-self-request", requester_id=actor_id,
            resource_id="fictional-resource", permission="read", reason="Self request"))
    with Session(engine) as session:
        scope = AccessRequestScope("fictional-self-request")
        decision = evaluate_authority(session, actor_id, Action.ACCESS_REQUEST_APPROVE, scope)
        assert decision.reason is Reason.SELF_APPROVAL_PROHIBITED


def test_rejection_does_not_inherit_unspecified_self_approval_prohibition(engine, actors):
    with Session(engine) as session, session.begin():
        session.add(AccessRequest(id="fictional-self-reject", requester_id=actors["reviewer"],
            resource_id="fictional-resource", permission="read", reason="Self request"))
    with Session(engine) as session:
        assert evaluate_authority(session, actors["reviewer"], Action.ACCESS_REQUEST_REJECT,
                                  AccessRequestScope("fictional-self-reject")).allowed


@pytest.mark.parametrize("action", [a for a in Action if a not in GLOBAL_ACTIONS])
def test_missing_required_department_or_request_scope_is_denied(engine, actors, action):
    with Session(engine) as session:
        decision = evaluate_authority(session, actors["operator"], action)
        assert not decision.allowed
        assert decision.reason is (Reason.ACCESS_REQUEST_SCOPE_REQUIRED if action in REQUEST_ACTIONS else Reason.DEPARTMENT_SCOPE_REQUIRED)


def test_request_department_is_resolved_from_resource_not_requester_home(engine, actors):
    with Session(engine) as session:
        decision = evaluate_authority(session, actors["reviewer"], Action.ACCESS_REQUEST_APPROVE,
                                      AccessRequestScope("fictional-request"))
        assert decision.allowed and decision.required_department_id == actors["finance"]
        assert session.get(User, actors["target"]).department_id == actors["hr"]
        mismatch = evaluate_authority(session, actors["reviewer"], Action.ACCESS_REQUEST_APPROVE,
                                      AccessRequestScope("fictional-request", actors["hr"]))
        assert mismatch.reason is Reason.SCOPE_MISMATCH
        assert evaluate_authority(session, actors["reviewer"], Action.ACCESS_REQUEST_APPROVE,
                                  DepartmentScope(actors["finance"])).reason is Reason.ACCESS_REQUEST_SCOPE_REQUIRED


@pytest.mark.parametrize("action", list(GLOBAL_ACTIONS))
def test_organization_actions_reject_department_scope(engine, actors, action):
    with Session(engine) as session:
        assert evaluate_authority(session, actors["operator"], action,
                                  DepartmentScope(actors["finance"])).reason is Reason.INVALID_SCOPE


@pytest.mark.parametrize("scope", [DepartmentScope(""), DepartmentScope(" missing "), DepartmentScope(None), DepartmentScope("missing")])
def test_invalid_or_unknown_department_fails_closed(engine, actors, scope):
    with Session(engine) as session:
        assert not evaluate_authority(session, actors["operator"], Action.DEPARTMENT_ADMINISTER, scope).allowed


@pytest.mark.parametrize("action", ["read", "write", "export", "EMERGENCY_OVERRIDE", None])
def test_business_data_or_unknown_actions_are_not_administrative_permissions(engine, actors, action):
    with Session(engine) as session:
        decision = evaluate_authority(session, actors["operator"], action, OrganizationScope())
        assert decision.reason is Reason.UNKNOWN_ACTION and decision.action is None


def test_super_admin_authority_does_not_grant_business_data_access(engine, actors):
    with Session(engine) as session:
        actor, resource = session.get(User, actors["operator"]), session.get(Resource, "fictional-resource")
        assert evaluate_authority(session, actor.id, Action.DEPARTMENT_RESOURCE_ADMINISTER,
                                  DepartmentScope(actors["finance"])).allowed
        assert not evaluate_access(actor, resource, "read", []).allowed


def test_employee_capabilities_are_independent_of_admin_denial(engine, actors):
    with Session(engine) as session:
        user = session.get(User, actors["reviewer"])
        resource = Resource(id="fictional-internal", name="Fixture", department_id=actors["hr"],
                            owner_id=actors["operator"], sensitivity="INTERNAL")
        assert not evaluate_authority(session, user.id, Action.IDENTITY_ADMINISTER, OrganizationScope()).allowed
        assert evaluate_access(user, resource, "read", []).allowed


def test_structured_evidence_is_minimal_and_immutable(engine, actors):
    with Session(engine) as session:
        decision = evaluate_authority(session, actors["reviewer"], Action.DEPARTMENT_SECURITY_MONITOR,
                                      DepartmentScope(actors["finance"]))
        assert decision.assignment_evidence.assignment_id == actors["assignment"]
        assert decision.assignment_evidence.department_id == actors["finance"]
        assert decision.assignment_evidence.assigned_at.tzinfo is not None
        assert "DO_NOT_AUDIT_HASH" not in repr(asdict(decision))
        assert "legacy" not in repr(asdict(decision))
        with pytest.raises(FrozenInstanceError):
            decision.allowed = False


def test_read_evaluation_never_writes_or_commits(engine, actors):
    statements, commits = [], []

    def observe(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement.strip().split()[0].upper())

    event.listen(engine, "before_cursor_execute", observe)
    try:
        with Session(engine) as session:
            event.listen(session, "after_commit", lambda s: commits.append(True))
            assert evaluate_authority(session, actors["reviewer"], Action.DEPARTMENT_ADMINISTER,
                                      DepartmentScope(actors["finance"])).allowed
    finally:
        event.remove(engine, "before_cursor_execute", observe)
    assert set(statements) == {"SELECT"} and commits == []


@pytest.mark.parametrize("action", list(Action))
def test_inactive_user_is_denied_for_every_action(engine, actors, action):
    with Session(engine) as session:
        decision = evaluate_authority(session, actors["inactive"], action, scope_for(action, actors))
        assert decision.reason is Reason.INACTIVE_USER


@pytest.mark.parametrize("user_id", [None, "", "missing-user"])
def test_unknown_actor_fails_closed(engine, actors, user_id):
    with Session(engine) as session:
        assert evaluate_authority(session, user_id, Action.IDENTITY_ADMINISTER,
                                  OrganizationScope()).reason is Reason.UNKNOWN_ACTOR


@pytest.mark.parametrize("action", [Action.DEPARTMENT_RESOURCE_ADMINISTER, Action.DEPARTMENT_GRANT_ADMINISTER,
                                   Action.DEPARTMENT_SECURITY_MONITOR, Action.DEPARTMENT_INCIDENT_INVESTIGATE])
def test_canonical_employee_owner_cannot_administer_owned_resource_department(engine, actors, action):
    with Session(engine) as session:
        assert session.get(Resource, "fictional-resource").owner_id == actors["target"]
        assert evaluate_authority(session, actors["target"], action,
                                  DepartmentScope(actors["finance"])).reason is Reason.ROLE_NOT_PERMITTED


def test_future_dated_assignment_does_not_grant_current_authority(engine, actors):
    with Session(engine) as session, session.begin():
        assignment = session.get(DepartmentAdminAssignment, actors["assignment"])
        assignment.assigned_at = datetime.now(timezone.utc) + timedelta(days=1)
    with Session(engine) as session:
        assert evaluate_authority(session, actors["reviewer"], Action.DEPARTMENT_ADMINISTER,
                                  DepartmentScope(actors["finance"])).reason is Reason.DEPARTMENT_ASSIGNMENT_REQUIRED


@pytest.mark.parametrize("scope", [AccessRequestScope("missing"), AccessRequestScope(""), AccessRequestScope("fictional-request", "")])
def test_unknown_or_invalid_request_scope_fails_closed(engine, actors, scope):
    with Session(engine) as session:
        assert not evaluate_authority(session, actors["operator"], Action.ACCESS_REQUEST_APPROVE, scope).allowed


@pytest.mark.parametrize("autobegin", [False, True])
def test_mutation_revalidation_requires_explicit_transaction(engine, actors, autobegin):
    with Session(engine) as session:
        if autobegin:
            session.get(User, actors["operator"])
        decision = revalidate_authority_for_mutation(session, actors["operator"],
                                                     Action.IDENTITY_ADMINISTER, OrganizationScope())
        assert decision.reason is Reason.TRANSACTION_REQUIRED


def test_unflushed_state_is_rejected_without_implicit_flush(engine, actors):
    with Session(engine) as session, session.begin():
        session.get(User, actors["operator"]).name = "Pending caller edit"
        decision = revalidate_authority_for_mutation(session, actors["operator"],
                                                     Action.IDENTITY_ADMINISTER, OrganizationScope())
        assert decision.reason is Reason.UNFLUSHED_STATE
        session.rollback()
    with Session(engine) as session:
        assert session.get(User, actors["operator"]).name == "operator"


@pytest.mark.parametrize("change", ["demotion", "revocation", "resource_department"])
def test_revalidation_rechecks_after_identity_lock(engine, actors, monkeypatch, change):
    real_lock = authority.lock_identity
    actor_id = actors["operator"] if change == "demotion" else actors["reviewer"]
    action = Action.IDENTITY_ADMINISTER if change == "demotion" else Action.ACCESS_REQUEST_APPROVE
    scope = OrganizationScope() if change == "demotion" else AccessRequestScope("fictional-request")

    def change_at_lock(session, user_id):
        state = real_lock(session, user_id)
        evidence = IdentityEvidence(actors["operator"], "Simulated interleaved identity change")
        if change == "demotion":
            change_organization_role(session, user_id, OrganizationRole.EMPLOYEE,
                                     expected_revision=state.revision, evidence=evidence)
        elif change == "revocation":
            revoke_department_admin_assignment(session, user_id, actors["assignment"],
                                                expected_revision=state.revision, evidence=evidence)
        else:
            session.execute(update(Resource).where(Resource.id == "fictional-resource").values(department_id=actors["hr"]))
        return state

    monkeypatch.setattr(authority, "lock_identity", change_at_lock)
    with Session(engine) as session, session.begin():
        assert evaluate_authority(session, actor_id, action, scope).allowed
        decision = revalidate_authority_for_mutation(session, actor_id, action, scope)
        assert not decision.allowed
        assert decision.reason is (Reason.ROLE_NOT_PERMITTED if change == "demotion" else Reason.DEPARTMENT_ASSIGNMENT_REQUIRED)
        if change == "resource_department":
            assert decision.required_department_id == actors["hr"]
        session.rollback()


def test_revalidation_leaves_commit_and_rollback_to_caller(engine, actors):
    commits = []
    with Session(engine) as session:
        event.listen(session, "after_commit", lambda s: commits.append(True))
        with pytest.raises(RuntimeError, match="Caller rolls back"):
            with session.begin():
                decision = revalidate_authority_for_mutation(session, actors["operator"],
                                                             Action.IDENTITY_ADMINISTER, OrganizationScope())
                assert decision.allowed and session.in_transaction()
                assert commits == []
                raise RuntimeError("Caller rolls back")
        assert not session.in_transaction()
    assert commits == []


def test_request_revalidation_locks_target_rows_in_postgresql_sql_without_connecting_to_postgresql(engine, actors):
    compiled = []

    def observe(connection, cursor, statement, parameters, context, executemany):
        if context.compiled is not None:
            compiled.append(str(context.compiled.statement.compile(dialect=postgresql.dialect())).lower())

    event.listen(engine, "before_cursor_execute", observe)
    try:
        with Session(engine) as session, session.begin():
            assert revalidate_authority_for_mutation(session, actors["reviewer"], Action.ACCESS_REQUEST_APPROVE,
                                                     AccessRequestScope("fictional-request")).allowed
    finally:
        event.remove(engine, "before_cursor_execute", observe)
    assert any("update users set organization_role=users.organization_role" in sql for sql in compiled)
    assert any("from access_requests" in sql and "for update" in sql for sql in compiled)
    assert any("from resources" in sql for sql in compiled)
    assert not any("from resources" in sql and "for update" in sql for sql in compiled)


def test_authority_does_not_claim_authentication_or_mfa_assurance(engine, actors):
    with Session(engine) as session:
        decision = evaluate_authority(session, actors["operator"], Action.IDENTITY_ADMINISTER, OrganizationScope())
        assert decision.allowed
        assert not hasattr(decision, "mfa_verified") and not hasattr(decision, "session_validated")


def test_documented_action_matrix_matches_executable_contract():
    document = (Path(__file__).resolve().parents[1] / "docs/organization_authority.md").read_text(encoding="utf-8")
    rows = {}
    for line in document.splitlines():
        if line.startswith("| "):
            fields = [field.strip() for field in line.split("|")[1:-1]]
            if fields[0] in {action.value for action in Action}:
                rows[fields[0]] = fields[1:]
    assert set(rows) == {action.value for action in Action}
    for action, policy in ACTION_MATRIX.items():
        scope, roles = rows[action.value]
        assert scope == policy.scope_kind.value
        assert {role.strip() for role in roles.split(",")} == {role.value for role in policy.permitted_roles}
