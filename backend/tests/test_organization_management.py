from datetime import datetime, timedelta, timezone
import json

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, event, select, text
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.core.database import Base, get_db
from app.core.security import create_access_token
from app.main import create_app
from app.models import (Department, User, DepartmentAdminAssignment, Resource, AuditEvent,
                        AuthenticationSession, UserAuthenticationState, MFACredential, RecoveryCode)
from app.services import organization_authority as authority
from app.services import identity_service as identity
from tests.authentication_support import configure, session_token

PREFIX = "/organization"


@pytest.fixture
def world(monkeypatch):
    configure(monkeypatch)
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    @event.listens_for(engine, "connect")
    def fk(connection, record):
        connection.execute("PRAGMA foreign_keys=ON")
    # Explicit nullable pre-0010 transition fixture; final-schema tests are separate.
    from tests.identity_transition_support import create_transition_schema
    create_transition_schema(engine)
    with Session(engine, expire_on_commit=False, autoflush=False) as db:
        db.add_all([Department(id=key, name=key.upper()) for key in ("hr", "eng", "archive", "empty")]); db.flush()
        for identifier, role, home, active in [
            ("super", "SUPER_ADMIN", "hr", True), ("super2", "SUPER_ADMIN", "eng", True),
            ("admin-hr", "DEPARTMENT_ADMIN", "eng", True), ("admin-eng", "DEPARTMENT_ADMIN", "hr", True),
            ("employee-hr", "EMPLOYEE", "hr", True), ("employee-eng", "EMPLOYEE", "eng", True),
            ("inactive", "EMPLOYEE", "archive", False), ("unmapped", None, "hr", True),
        ]:
            db.add(User(id=identifier, name=identifier, email=f"{identifier}@example.com", password_hash="not-a-login-credential",
                        role="ADMIN", organization_role=role, department_id=home, active=active))
        db.flush()
        now = datetime.now(timezone.utc)
        db.add_all([DepartmentAdminAssignment(id="a-hr", user_id="admin-hr", department_id="hr", assigned_by="super"),
                    DepartmentAdminAssignment(id="a-eng", user_id="admin-eng", department_id="eng", assigned_by="super"),
                    DepartmentAdminAssignment(id="a-history", user_id="admin-hr", department_id="archive", assigned_by="super",
                                              assigned_at=now - timedelta(days=1), revoked_at=now - timedelta(hours=1), revoked_by="super2")])
        db.add(Resource(id="resource", name="Sensitive", department_id="hr", owner_id="employee-hr", sensitivity="CRITICAL"))
        db.commit()
        app = create_app()
        app.dependency_overrides[get_db] = lambda: db
        with TestClient(app, base_url="https://testserver", client=("127.0.0.1", 50000)) as client:
            yield db, client, app
    engine.dispose()


def headers(db, actor="super"):
    return {"Authorization": "Bearer " + session_token(db, actor)}


def employee_revision(db, user_id):
    return identity.read_identity_state(db, user_id).revision


def change(db, target_user_id, **extra):
    return {"expected_revision": employee_revision(db, target_user_id), "reason": "Fictional reviewed change", **extra}


def department(db, client, key):
    response = client.get(f"{PREFIX}/departments/{key}", headers=headers(db))
    assert response.status_code == 200, response.text
    return {"expected_revision": response.json()["revision"], "reason": "Fictional reviewed department change"}


@pytest.mark.parametrize("actor,expected", [("super", {"hr", "eng", "archive", "empty"}), ("admin-hr", {"hr"}), ("admin-eng", {"eng"})])
def test_department_reads_use_explicit_assignments_not_home_department(world, actor, expected):
    db, client, _ = world
    response = client.get(f"{PREFIX}/departments?limit=1", headers=headers(db, actor))
    assert response.status_code == 200
    assert response.json()["total"] == len(expected)
    assert {row["id"] for row in response.json()["items"]} <= expected
    rows = client.get(f"{PREFIX}/departments?offset=1&limit=100", headers=headers(db, actor)).json()
    assert rows["total"] == len(expected)
    for identifier in ("hr", "eng"):
        assert client.get(f"{PREFIX}/departments/{identifier}", headers=headers(db, actor)).status_code == (200 if identifier in expected else 404)


def test_super_department_create_update_deactivate_preserves_history(world):
    db, client, _ = world
    response = client.post(f"{PREFIX}/departments", json={"name": "New department", "description": "Test", "reason": "Test creation"}, headers=headers(db))
    assert response.status_code == 201, response.text
    created = response.json()
    assert client.post(f"{PREFIX}/departments", json={"name": " new DEPARTMENT ", "reason": "Duplicate"}, headers=headers(db)).status_code == 409
    response = client.patch(f"{PREFIX}/departments/{created['id']}", json={"expected_revision": created["revision"], "reason": "Metadata", "description": "Updated"}, headers=headers(db))
    assert response.status_code == 200
    assert response.json()["revision"] != created["revision"]
    # Only inactive employees and revoked assignment history reference archive.
    result = client.post(f"{PREFIX}/departments/archive/deactivate", json=department(db, client, "archive"), headers=headers(db))
    assert result.status_code == 200, result.text
    assert result.json()["active"] is False
    db.expire_all()
    assert db.get(User, "inactive").department_id == "archive"
    assert db.get(DepartmentAdminAssignment, "a-history").revoked_by == "super2"
    assert client.post(f"{PREFIX}/departments/archive/reactivate", json={"expected_revision": result.json()["revision"], "reason": "Reopen"}, headers=headers(db)).status_code == 200
    assert client.post(f"{PREFIX}/departments/hr/deactivate", json=department(db, client, "hr"), headers=headers(db)).status_code == 409


@pytest.mark.parametrize("actor", ["admin-hr", "admin-eng", "employee-hr"])
@pytest.mark.parametrize("operation", ["create_department", "update_department", "create_employee", "profile", "role", "deactivate", "reactivate", "assign", "revoke"])
def test_non_super_cannot_manage_global_identity_or_assignments(world, actor, operation):
    db, client, _ = world
    operations = {
        "create_department": ("post", "/departments", {"name": "No", "reason": "Denied"}),
        "update_department": ("patch", "/departments/hr", {**department(db, client, "hr"), "name": "No"}),
        "create_employee": ("post", "/employees", {"name": "No", "email": "no@example.com", "home_department_id": "hr", "reason": "Denied"}),
        "profile": ("patch", "/employees/employee-hr", change(db, "employee-hr", name="No")),
        "role": ("post", "/employees/employee-hr/role", change(db, "employee-hr", organization_role="SUPER_ADMIN")),
        "deactivate": ("post", "/employees/employee-hr/deactivate", change(db, "employee-hr")),
        "reactivate": ("post", "/employees/inactive/reactivate", change(db, "inactive")),
        "assign": ("post", "/assignments", change(db, "admin-eng", user_id="admin-eng", department_id="hr")),
        "revoke": ("post", "/assignments/a-hr/revoke", change(db, "admin-hr")),
    }
    method, path, payload = operations[operation]
    assert getattr(client, method)(PREFIX + path, json=payload, headers=headers(db, actor)).status_code == 403


def test_employee_queries_scope_before_search_filter_count_and_pagination(world):
    db, client, _ = world
    hr_ids = set(db.scalars(select(User.id).where(User.department_id == "hr")))
    response = client.get(f"{PREFIX}/employees?limit=1", headers=headers(db, "admin-hr"))
    assert response.status_code == 200 and response.json()["total"] == len(hr_ids)
    assert {row["id"] for row in response.json()["items"]} <= hr_ids
    for query in ("home_department_id=eng", "q=employee-eng", "q=%25", "offset=100"):
        response = client.get(f"{PREFIX}/employees?{query}", headers=headers(db, "admin-hr"))
        assert response.status_code == 200 and response.json()["items"] == []
        if query != "offset=100": assert response.json()["total"] == 0
    assert client.get(f"{PREFIX}/employees/employee-eng", headers=headers(db, "admin-hr")).status_code == 404
    assert client.get(f"{PREFIX}/employees/nonexistent", headers=headers(db, "admin-hr")).status_code == 404
    assert client.get(f"{PREFIX}/employees?limit=101", headers=headers(db)).status_code == 422


def test_employee_creation_is_inactive_canonical_and_not_authentication(world):
    db, client, app = world
    payload = {"name": "New Employee", "email": "NEW@example.com", "home_department_id": "hr", "reason": "Explicit new identity"}
    response = client.post(f"{PREFIX}/employees", json=payload, headers=headers(db))
    assert response.status_code == 201, response.text
    data = response.json()
    assert not data["active"] and data["organization_role"] == "EMPLOYEE" and data["requires_trusted_onboarding"]
    assert data["email"] == "new@example.com"
    created_id = data["id"]
    db.expire_all()
    assert db.get(User, created_id).role == "EMPLOYEE"
    assert db.get(UserAuthenticationState, created_id) is None
    assert db.query(MFACredential).filter_by(user_id=created_id).count() == 0
    assert db.query(RecoveryCode).filter_by(user_id=created_id).count() == 0
    assert db.query(AuthenticationSession).filter_by(user_id=created_id).count() == 0
    assert getattr(app.state, "enrollment_authorizer", None) is None
    assert client.post(f"{PREFIX}/employees/{created_id}/reactivate", json=change(db, created_id), headers=headers(db)).status_code == 409
    assert client.post(f"{PREFIX}/employees", json=payload, headers=headers(db)).status_code == 409
    for forbidden in ("password", "password_hash", "security_generation", "organization_role"):
        bad = client.post(f"{PREFIX}/employees", json={**payload, forbidden: "DO-NOT-ECHO-SECRET"}, headers=headers(db))
        assert bad.status_code == 422 and "DO-NOT-ECHO-SECRET" not in bad.text


def test_profiles_role_cas_and_security_generation_are_atomic(world):
    db, client, _ = world
    old_header = headers(db, "employee-hr")
    original = employee_revision(db, "employee-hr")
    response = client.patch(f"{PREFIX}/employees/employee-hr", json={"expected_revision": original, "name": "Updated employee", "reason": "Profile correction"}, headers=headers(db))
    assert response.status_code == 200, response.text
    assert response.json()["revision"] != original
    assert client.get("/auth/me", headers=old_header).status_code == 200  # Name-only update preserves sessions.
    assert client.post(f"{PREFIX}/employees/employee-hr/role", json={"expected_revision": original, "organization_role": "DEPARTMENT_ADMIN", "reason": "Stale"}, headers=headers(db)).status_code == 409
    role = client.post(f"{PREFIX}/employees/employee-hr/role", json=change(db, "employee-hr", organization_role="DEPARTMENT_ADMIN"), headers=headers(db))
    assert role.status_code == 200, role.text
    assert client.get("/auth/me", headers=old_header).status_code == 401
    db.expire_all()
    assert db.get(User, "employee-hr").role == "ADMIN"  # Legacy provenance unchanged.
    assert db.get(UserAuthenticationState, "employee-hr").security_generation == 1
    assert db.query(AuditEvent).filter_by(action="ORGANIZATION_ROLE_CHANGED").count() == 1


@pytest.mark.parametrize("protected", ["organization_role", "role", "active", "security_generation", "password_hash", "department_admin_assignments"])
def test_profile_mass_assignment_rejected(world, protected):
    db, client, _ = world
    response = client.patch(f"{PREFIX}/employees/employee-hr", json=change(db, "employee-hr", **{protected: "FORBIDDEN"}), headers=headers(db))
    assert response.status_code == 422 and "FORBIDDEN" not in response.text


@pytest.mark.parametrize("role", ["ADMIN", "SECURITY_ANALYST", "super_admin", "", None])
def test_noncanonical_role_rejected(world, role):
    db, client, _ = world
    assert client.post(f"{PREFIX}/employees/employee-hr/role", json=change(db, "employee-hr", organization_role=role), headers=headers(db)).status_code == 422


def test_assignments_multiple_admins_departments_revoke_and_history(world):
    db, client, _ = world
    response = client.post(f"{PREFIX}/assignments", json=change(db, "admin-eng", user_id="admin-eng", department_id="hr"), headers=headers(db))
    assert response.status_code == 201, response.text
    response = client.post(f"{PREFIX}/assignments", json=change(db, "admin-hr", user_id="admin-hr", department_id="empty"), headers=headers(db))
    assert response.status_code == 201, response.text
    assignment = response.json()
    assert client.post(f"{PREFIX}/assignments", json=change(db, "admin-hr", user_id="admin-hr", department_id="empty"), headers=headers(db)).status_code == 409
    target_header = headers(db, "admin-hr")
    assert client.get(f"{PREFIX}/departments/empty", headers=target_header).status_code == 200
    revoked = client.post(f"{PREFIX}/assignments/{assignment['id']}/revoke", json=change(db, "admin-hr"), headers=headers(db))
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["revoked_by"] == "super" and revoked.json()["revoked_at"]
    assert client.get(f"{PREFIX}/departments/empty", headers=target_header).status_code == 401
    assert client.get(f"{PREFIX}/departments/empty", headers=headers(db, "admin-hr")).status_code == 404
    history = client.get(f"{PREFIX}/assignments?user_id=admin-hr", headers=headers(db)).json()
    assert assignment["id"] in {item["id"] for item in history["items"]}
    assert db.query(DepartmentAdminAssignment).filter_by(department_id="hr", revoked_at=None).count() == 2
    assert client.post(f"{PREFIX}/employees/admin-hr/role", json=change(db, "admin-hr", organization_role="EMPLOYEE"), headers=headers(db)).status_code == 409


@pytest.mark.parametrize("target", ["employee-hr", "unmapped", "super"])
def test_only_explicit_department_admin_receives_assignments(world, target):
    db, client, _ = world
    response = client.post(f"{PREFIX}/assignments", json=change(db, target, user_id=target, department_id="empty"), headers=headers(db))
    assert response.status_code == (403 if target == "super" else 409)


def test_assignment_reads_and_home_department_are_separate_and_scoped(world):
    db, client, _ = world
    assert client.get(f"{PREFIX}/assignments", headers=headers(db, "admin-hr")).status_code == 403
    own = client.get(f"{PREFIX}/departments/hr/assignments", headers=headers(db, "admin-hr"))
    assert own.status_code == 200 and own.json()["total"] == 1
    assert client.get(f"{PREFIX}/departments/eng/assignments", headers=headers(db, "admin-hr")).status_code == 404
    assert client.get(f"{PREFIX}/employees/admin-hr/assignments", headers=headers(db, "admin-hr")).status_code == 404  # Home ENG.
    # admin-eng's home HR permits profile visibility, not disclosure of its ENG assignment.
    visible = client.get(f"{PREFIX}/employees/admin-eng/assignments", headers=headers(db, "admin-hr"))
    assert visible.status_code == 200 and visible.json()["total"] == 0


def test_missing_mfa_legacy_tokens_and_unmapped_identity_are_rejected(world):
    db, client, _ = world
    for path in ("/departments", "/employees", "/assignments"):
        assert client.get(PREFIX + path).status_code == 401
        assert client.get(PREFIX + path, headers={"Authorization": "Bearer " + create_access_token("super")}).status_code == 401
        assert client.get(PREFIX + path, headers=headers(db, "unmapped")).status_code == 401


def test_lifecycle_and_last_super_admin_protection(world):
    db, client, _ = world
    old = headers(db, "employee-hr")
    assert client.post(f"{PREFIX}/employees/employee-hr/deactivate", json=change(db, "employee-hr"), headers=headers(db)).status_code == 200
    assert client.get("/auth/me", headers=old).status_code == 401
    assert client.post(f"{PREFIX}/employees/employee-hr/reactivate", json=change(db, "employee-hr"), headers=headers(db)).status_code == 200
    assert client.get("/auth/me", headers=old).status_code == 401
    assert client.post(f"{PREFIX}/employees/super2/deactivate", json=change(db, "super2"), headers=headers(db)).status_code == 200
    assert client.post(f"{PREFIX}/employees/super/deactivate", json=change(db, "super"), headers=headers(db)).status_code == 409
    assert client.post(f"{PREFIX}/employees/super/role", json=change(db, "super", organization_role="EMPLOYEE"), headers=headers(db)).status_code == 409


@pytest.mark.parametrize("operation", ["role", "profile", "assignment", "department"])
def test_required_audit_failure_rolls_back_security_mutation(world, operation):
    db, client, _ = world
    user_revision = employee_revision(db, "employee-hr")
    token = headers(db, "employee-hr")
    actor = headers(db)
    payload = department(db, client, "empty")
    before = db.query(AuditEvent).count()
    def fail(*args): raise RuntimeError("audit unavailable")
    event.listen(AuditEvent, "before_insert", fail)
    try:
        if operation == "role":
            response = client.post(f"{PREFIX}/employees/employee-hr/role", json=change(db, "employee-hr", organization_role="DEPARTMENT_ADMIN"), headers=actor)
        elif operation == "profile":
            response = client.patch(f"{PREFIX}/employees/employee-hr", json=change(db, "employee-hr", email="changed@example.com"), headers=actor)
        elif operation == "assignment":
            response = client.post(f"{PREFIX}/assignments", json=change(db, "admin-hr", user_id="admin-hr", department_id="empty"), headers=actor)
        else:
            response = client.post(f"{PREFIX}/departments/empty/deactivate", json=payload, headers=actor)
    finally:
        event.remove(AuditEvent, "before_insert", fail)
    assert response.status_code == 503
    db.expire_all()
    assert employee_revision(db, "employee-hr") == user_revision
    assert db.query(AuditEvent).count() == before
    assert db.get(Department, "empty").active
    assert db.query(DepartmentAdminAssignment).filter_by(department_id="empty").count() == 0
    assert client.get("/auth/me", headers=token).status_code == 200


def test_authority_errors_and_interleaved_demotion_fail_closed(world, monkeypatch):
    db, client, _ = world
    actor = headers(db)
    original = authority.lock_identity
    def interleave(tx, actor_id):
        tx.execute(text("UPDATE users SET organization_role='EMPLOYEE' WHERE id='super'"))
        return original(tx, actor_id)
    monkeypatch.setattr(authority, "lock_identity", interleave)
    response = client.post(f"{PREFIX}/departments", json={"name": "Must not persist", "reason": "Race"}, headers=actor)
    assert response.status_code == 403
    assert db.query(Department).filter_by(name="Must not persist").count() == 0
    def unavailable(*args, **kwargs): raise RuntimeError("authority unavailable")
    monkeypatch.setattr(authority, "evaluate_authority", unavailable)
    assert client.get(f"{PREFIX}/departments", headers=actor).status_code == 503


@pytest.mark.parametrize("field,value", [("email", "changed@example.com"), ("home_department_id", "eng")])
def test_sensitive_profile_changes_invalidate_sessions_and_preserve_relationships(world, field, value):
    db, client, _ = world
    token = headers(db, "employee-hr")
    response = client.patch(f"{PREFIX}/employees/employee-hr", json=change(db, "employee-hr", **{field: value}), headers=headers(db))
    assert response.status_code == 200, response.text
    assert client.get("/auth/me", headers=token).status_code == 401
    db.expire_all()
    assert db.get(Resource, "resource").owner_id == "employee-hr"
    assert db.get(User, "employee-hr").role == "ADMIN"
    assert db.get(UserAuthenticationState, "employee-hr").security_generation == 1


def test_late_session_invalidation_audit_failure_rolls_back_entire_role_transaction(world):
    db, client, _ = world
    target_token = headers(db, "employee-hr")
    actor_token = headers(db)
    before = employee_revision(db, "employee-hr")
    def fail(mapper, connection, row):
        if row.action == "AUTH_GENERATION_CHANGED": raise RuntimeError("late security audit failure")
    event.listen(AuditEvent, "before_insert", fail)
    try:
        response = client.post(f"{PREFIX}/employees/employee-hr/role", json=change(db, "employee-hr", organization_role="DEPARTMENT_ADMIN"), headers=actor_token)
    finally:
        event.remove(AuditEvent, "before_insert", fail)
    assert response.status_code == 503
    db.expire_all()
    assert employee_revision(db, "employee-hr") == before
    assert db.get(User, "employee-hr").organization_role.value == "EMPLOYEE"
    assert db.get(UserAuthenticationState, "employee-hr").security_generation == 0
    assert db.query(AuditEvent).filter_by(action="ORGANIZATION_ROLE_CHANGED").count() == 0
    assert client.get("/auth/me", headers=target_token).status_code == 200


def test_revocation_then_reassignment_retains_history_and_allows_explicit_role_change(world):
    db, client, _ = world
    revoked = client.post(f"{PREFIX}/assignments/a-hr/revoke", json=change(db, "admin-hr"), headers=headers(db))
    assert revoked.status_code == 200
    changed = client.post(f"{PREFIX}/employees/admin-hr/role", json=change(db, "admin-hr", organization_role="EMPLOYEE"), headers=headers(db))
    assert changed.status_code == 200
    assert client.post(f"{PREFIX}/employees/admin-hr/role", json=change(db, "admin-hr", organization_role="DEPARTMENT_ADMIN"), headers=headers(db)).status_code == 200
    reassigned = client.post(f"{PREFIX}/assignments", json=change(db, "admin-hr", user_id="admin-hr", department_id="hr"), headers=headers(db))
    assert reassigned.status_code == 201 and reassigned.json()["id"] != "a-hr"
    db.expire_all()
    assert db.get(DepartmentAdminAssignment, "a-hr").revoked_by == "super"
    assert db.query(DepartmentAdminAssignment).filter_by(user_id="admin-hr", department_id="hr").count() == 2


def test_inactive_department_denies_central_authority_and_new_assignment(world):
    db, client, _ = world
    assert client.post(f"{PREFIX}/departments/empty/deactivate", json=department(db, client, "empty"), headers=headers(db)).status_code == 200
    assert client.post(f"{PREFIX}/assignments", json=change(db, "admin-hr", user_id="admin-hr", department_id="empty"), headers=headers(db)).status_code == 409
    for actor in ("super", "admin-hr"):
        decision = authority.evaluate_authority(db, actor, authority.AdministrativeAction.DEPARTMENT_ADMINISTER, authority.DepartmentScope("empty"))
        assert not decision.allowed and decision.reason is authority.AuthorityReason.INACTIVE_DEPARTMENT
    # The primitive itself also enforces lifecycle, independently of the API.
    db.commit()
    with pytest.raises(identity.IdentityError, match="must be active"), db.begin():
        identity.create_department_admin_assignment(db, "admin-hr", "empty", expected_revision=employee_revision(db, "admin-hr"),
            evidence=identity.IdentityEvidence("super", "Explicit primitive lifecycle test"))


def test_responses_omit_credential_material_and_super_gets_no_business_access(world):
    db, client, _ = world
    for path in ("/employees", "/employees/employee-hr", "/departments", "/assignments"):
        response = client.get(PREFIX + path, headers=headers(db))
        assert response.status_code == 200
        encoded = json.dumps(response.json())
        for forbidden in ("password_hash", "secret_ciphertext", "code_hash", "security_generation", "recovery_codes", "mfa_verified_at"):
            assert forbidden not in encoded
    assert client.get("/resources/resource", headers=headers(db)).status_code == 403


def test_correct_typed_actions_and_authoritative_scopes_are_used(world, monkeypatch):
    db, client, _ = world
    original = authority.evaluate_authority
    calls = []
    def capture(session, actor_id, action, scope=None):
        calls.append((actor_id, action, scope))
        return original(session, actor_id, action, scope)
    monkeypatch.setattr(authority, "evaluate_authority", capture)
    assert client.post(f"{PREFIX}/departments", json={"name": "Matrix test", "reason": "Action"}, headers=headers(db)).status_code == 201
    assert any(action is authority.AdministrativeAction.ORGANIZATION_ADMINISTER and isinstance(scope, authority.OrganizationScope) for _, action, scope in calls)
    calls.clear()
    assert client.post(f"{PREFIX}/employees/employee-hr/role", json=change(db, "employee-hr", organization_role="DEPARTMENT_ADMIN"), headers=headers(db)).status_code == 200
    assert any(action is authority.AdministrativeAction.IDENTITY_ADMINISTER for _, action, _ in calls)
    calls.clear()
    assert client.post(f"{PREFIX}/assignments", json=change(db, "admin-eng", user_id="admin-eng", department_id="hr"), headers=headers(db)).status_code == 201
    assert any(action is authority.AdministrativeAction.DEPARTMENT_ASSIGNMENTS_ADMINISTER for _, action, _ in calls)
    calls.clear()
    assert client.get(f"{PREFIX}/departments/hr", headers=headers(db, "admin-hr")).status_code == 200
    assert any(action is authority.AdministrativeAction.DEPARTMENT_ADMINISTER and isinstance(scope, authority.DepartmentScope) and scope.department_id == "hr" for _, action, scope in calls)


def test_real_cookie_mfa_authentication_and_csrf_protect_new_endpoints(monkeypatch):
    from tests.test_mfa_workflows import world as mfa_world, enroll, post
    # Reuse that fixture's implementation through its undecorated generator,
    # including real HTTP enrollment/TOTP and a test-only independent authorizer.
    generator = mfa_world.__wrapped__(monkeypatch)
    world = next(generator)
    engine, client, app = world
    try:
        enroll(world, "super")
        payload = {"name": "Cookie-managed department", "reason": "Test real MFA integration"}
        assert client.post(PREFIX + "/departments", json=payload).status_code == 403
        response = post(client, PREFIX + "/departments", payload)
        assert response.status_code == 201, response.text
        assert client.get(PREFIX + "/departments").status_code == 200
    finally:
        generator.close()


def test_super_cannot_expand_own_home_department_policy_scope(world):
    db, client, _ = world
    before = employee_revision(db, "super")
    response = client.patch(f"{PREFIX}/employees/super", json=change(db, "super", home_department_id="eng"), headers=headers(db))
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "SELF_SCOPE_CHANGE_PROHIBITED"
    db.expire_all()
    assert db.get(User, "super").department_id == "hr" and employee_revision(db, "super") == before


def test_unenrolled_super_does_not_make_last_mfa_super_safe_to_disable(world):
    db, client, _ = world
    # super2 is a canonical active identity but has no MFA credential; counting
    # it as an available administrator would permit an avoidable lockout.
    response = client.post(f"{PREFIX}/employees/super/deactivate", json=change(db, "super"), headers=headers(db))
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "LAST_SUPER_ADMIN_PROTECTED"
