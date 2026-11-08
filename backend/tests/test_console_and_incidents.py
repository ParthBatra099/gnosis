import pytest
from sqlalchemy import event
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base, get_db
from app.core.security import hash_password
from tests.authentication_support import session_token, browser_post
from app.main import app
from app.models.department import Department
from app.models.department_admin_assignment import DepartmentAdminAssignment
from app.models.incident import Incident
from app.models.incident_event import IncidentEvent
from app.models.resource import Resource
from app.models.security_event import SecurityEvent
from app.models.user import User
from app.models.audit_event import AuditEvent


@pytest.mark.parametrize("payload", [
    {"status": "INVESTIGATING"}, {"status": "RESOLVED", "resolution_notes": "Self cleared"},
    {"status": "CLOSED"}, {"resolution_notes": "Self cleared"}, {"assigned_to_id": "self"},
])
def test_automatic_reporter_cannot_mutate_incident(client, db_session, payload):
    user = db_session.query(User).filter_by(email="eng_req@gnosis.com").one()
    resource = db_session.query(Resource).filter_by(name="Master Keys").one()
    headers = {"Authorization": f"Bearer {session_token(db_session, subject=user.id)}"}
    assert client.get(f"/resources/{resource.id}", headers=headers).status_code == 403
    incident = db_session.query(Incident).filter_by(resource_id=resource.id).one()
    assert incident.reporter_id == user.id
    if payload.get("assigned_to_id") == "self":
        payload = {"assigned_to_id": user.id}
    response = client.patch(f"/console/incidents/{incident.id}", json=payload, headers=headers)
    assert response.status_code == 404
    assert client.post(f"/console/incidents/{incident.id}/events",
                       json={"security_event_ids": []}, headers=headers).status_code == 404
    db_session.refresh(incident)
    assert incident.status == "OPEN"
    assert incident.assigned_to_id is None
    assert incident.resolution_notes is None
    # Unit 4 supersedes reporter-only administrative viewing as well.
    assert client.get(f"/console/incidents/{incident.id}", headers=headers).status_code == 404


def test_explicit_assignee_with_department_authority_can_update_incident(client, db_session):
    user = db_session.query(User).filter_by(email="eng_req@gnosis.com").one()
    resource = db_session.query(Resource).filter_by(name="HR Payroll Data").one()
    user.organization_role = "DEPARTMENT_ADMIN"
    db_session.add(DepartmentAdminAssignment(user_id=user.id, department_id=resource.department_id,
                                            assigned_by=user.id))
    incident = Incident(title="Assigned", description="Test", severity="LOW",
                        resource_id=resource.id, assigned_to_id=user.id)
    db_session.add(incident)
    db_session.commit()
    headers = {"Authorization": f"Bearer {session_token(db_session, subject=user.id)}"}
    response = client.patch(f"/console/incidents/{incident.id}",
                            json={"status": "INVESTIGATING"}, headers=headers)
    assert response.status_code == 200


def test_incident_detail_filters_each_linked_event(client, db_session):
    user = db_session.query(User).filter_by(email="eng_req@gnosis.com").one()
    owner = db_session.query(User).filter_by(email="hr_owner@gnosis.com").one()
    resource = db_session.query(Resource).filter_by(name="HR Payroll Data").one()
    incident = Incident(title="Shared", description="Test", severity="HIGH",
                        resource_id=resource.id, reporter_id=user.id)
    visible = SecurityEvent(event_type="TEST", severity="LOW", actor_id=user.id,
                            resource_id=resource.id, description="Own evidence")
    hidden = SecurityEvent(event_type="TEST", severity="LOW", actor_id=owner.id,
                           resource_id=resource.id, description="Another actor's evidence")
    db_session.add_all([incident, visible, hidden])
    db_session.flush()
    db_session.add_all([IncidentEvent(incident_id=incident.id, security_event_id=e.id)
                        for e in (visible, hidden)])
    db_session.commit()
    for principal, expected in [(user, None), (owner, {visible.id, hidden.id})]:
        headers = {"Authorization": f"Bearer {session_token(db_session, subject=principal.id)}"}
        response = client.get(f"/console/incidents/{incident.id}", headers=headers)
        assert response.status_code == (404 if expected is None else 200)
        if expected is not None:
            assert {e["id"] for e in response.json()["security_events"]} == expected
    assert db_session.query(IncidentEvent).count() == 2


@pytest.mark.parametrize("invalid", ["missing", "unauthorized"])
def test_invalid_create_evidence_leaves_no_partial_incident(client, db_session, invalid):
    owner = db_session.query(User).filter_by(email="hr_owner@gnosis.com").one()
    other = db_session.query(User).filter_by(email="eng_req@gnosis.com").one()
    resource = db_session.query(Resource).filter_by(name="HR Payroll Data").one()
    valid = SecurityEvent(event_type="TEST", severity="LOW", resource_id=resource.id,
                          description="Valid")
    hidden = SecurityEvent(event_type="TEST", severity="LOW", actor_id=other.id,
                           description="Not authorized")
    db_session.add_all([valid, hidden])
    db_session.commit()
    before = (db_session.query(Incident).count(), db_session.query(IncidentEvent).count())
    headers = {"Authorization": f"Bearer {session_token(db_session, subject=owner.id)}"}
    response = client.post("/console/incidents", headers=headers, json={
        "title": "Must not persist", "description": "Test", "severity": "LOW",
        "resource_id": resource.id,
        "security_event_ids": [valid.id, "missing-id" if invalid == "missing" else hidden.id],
    })
    assert response.status_code == (404 if invalid == "missing" else 403)
    assert (db_session.query(Incident).count(), db_session.query(IncidentEvent).count()) == before


def test_create_incident_commits_unique_links_and_audit(client, db_session):
    owner = db_session.query(User).filter_by(email="hr_owner@gnosis.com").one()
    resource = db_session.query(Resource).filter_by(name="HR Payroll Data").one()
    evidence = SecurityEvent(event_type="TEST", severity="LOW", resource_id=resource.id,
                             description="Retained evidence")
    db_session.add(evidence)
    db_session.commit()
    headers = {"Authorization": f"Bearer {session_token(db_session, subject=owner.id)}"}
    response = client.post("/console/incidents", headers=headers, json={
        "title": "Valid", "description": "Test", "severity": "LOW",
        "resource_id": resource.id, "security_event_ids": [evidence.id, evidence.id],
    })
    assert response.status_code == 201
    assert db_session.query(IncidentEvent).count() == 1
    audit = db_session.query(AuditEvent).filter_by(action="INCIDENT_CREATED").one()
    assert audit.context_data["incident_id"] == response.json()["id"]
    assert db_session.get(SecurityEvent, evidence.id) is not None


def test_link_persistence_failure_rolls_back_new_incident(client, db_session):
    owner = db_session.query(User).filter_by(email="hr_owner@gnosis.com").one()
    resource = db_session.query(Resource).filter_by(name="HR Payroll Data").one()
    evidence = SecurityEvent(event_type="TEST", severity="LOW", resource_id=resource.id,
                             description="Retained evidence")
    db_session.add(evidence)
    db_session.commit()
    evidence_id = evidence.id
    attempts = []

    def fail_link(mapper, connection, link):
        attempts.append(link.security_event_id)
        raise RuntimeError("Simulated link persistence failure")

    event.listen(IncidentEvent, "before_insert", fail_link)
    try:
        with pytest.raises(RuntimeError, match="link persistence failure"):
            client.post("/console/incidents", json={
                "title": "Atomic", "description": "Test", "severity": "LOW",
                "resource_id": resource.id, "security_event_ids": [evidence_id],
            }, headers={"Authorization": f"Bearer {session_token(db_session, subject=owner.id)}"})
    finally:
        event.remove(IncidentEvent, "before_insert", fail_link)
    assert attempts == [evidence_id]
    assert db_session.is_active
    assert db_session.query(Incident).count() == 0
    assert db_session.query(IncidentEvent).count() == 0
    assert db_session.get(SecurityEvent, evidence_id) is not None


@pytest.fixture
def db_session():
    """Isolated SQLite in-memory DB for Phase 4 console and incident tests."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()

    # Seed departments
    hr_dept = Department(name="Human Resources")
    eng_dept = Department(name="Engineering")
    session.add_all([hr_dept, eng_dept])
    session.commit()

    # Seed users
    hr_owner = User(
        name="HR Owner",
        email="hr_owner@gnosis.com",
        password_hash=hash_password("Pass123!"),
        role="EMPLOYEE",
        organization_role="EMPLOYEE",
        department_id=hr_dept.id,
        active=True,
    )
    eng_user = User(
        name="Eng Requester",
        email="eng_req@gnosis.com",
        password_hash=hash_password("Pass123!"),
        role="EMPLOYEE",
        organization_role="EMPLOYEE",
        department_id=eng_dept.id,
        active=True,
    )
    # Unit 4: this test administrator is explicitly assigned, independent of ownership.
    hr_owner.organization_role = "DEPARTMENT_ADMIN"
    eng_user.organization_role = "EMPLOYEE"
    session.add_all([hr_owner, eng_user])
    session.commit()
    session.add(DepartmentAdminAssignment(user_id=hr_owner.id, department_id=hr_dept.id,
                                          assigned_by=hr_owner.id))
    session.commit()

    # Seed resources
    hr_res = Resource(
        name="HR Payroll Data",
        description="Payroll details",
        department_id=hr_dept.id,
        owner_id=hr_owner.id,
        sensitivity="INTERNAL",
    )
    crit_res = Resource(
        name="Master Keys",
        description="Root keys",
        department_id=hr_dept.id,
        owner_id=hr_owner.id,
        sensitivity="CRITICAL",
    )
    session.add_all([hr_res, crit_res])
    session.commit()

    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, base_url="https://testserver", client=("127.0.0.1", 50000)) as c:
        yield c
    app.dependency_overrides.clear()


def test_manual_incident_creation_success(client, db_session):
    hr_owner = db_session.query(User).filter_by(email="hr_owner@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Payroll Data").first()
    token = session_token(db_session, subject=hr_owner.id)

    resp = client.post(
        "/console/incidents",
        json={
            "title": "Unusual Access Pattern",
            "description": "Investigating access attempts",
            "severity": "HIGH",
            "resource_id": res.id,
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] == "OPEN"
    assert data["severity"] == "HIGH"


def test_unauthorized_incident_access_denied(client, db_session):
    eng_user = db_session.query(User).filter_by(email="eng_req@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Payroll Data").first()
    token = session_token(db_session, subject=eng_user.id)

    # Eng user attempts to create incident for HR resource -> 403
    resp = client.post(
        "/console/incidents",
        json={
            "title": "Unauthorized Attempt",
            "description": "Test",
            "severity": "LOW",
            "resource_id": res.id,
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


def test_incident_status_workflow(client, db_session):
    hr_owner = db_session.query(User).filter_by(email="hr_owner@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Payroll Data").first()
    token = session_token(db_session, subject=hr_owner.id)

    # 1. Create OPEN incident
    inc_resp = client.post(
        "/console/incidents",
        json={"title": "Workflow Test", "description": "Test", "severity": "MEDIUM", "resource_id": res.id},
        headers={"Authorization": f"Bearer {token}"},
    )
    inc_id = inc_resp.json()["id"]

    # 2. OPEN -> INVESTIGATING (Success)
    patch1 = client.patch(
        f"/console/incidents/{inc_id}",
        json={"status": "INVESTIGATING"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert patch1.status_code == 200
    assert patch1.json()["status"] == "INVESTIGATING"

    # 3. INVESTIGATING -> RESOLVED (Requires notes)
    patch2_fail = client.patch(
        f"/console/incidents/{inc_id}",
        json={"status": "RESOLVED"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert patch2_fail.status_code == 400

    patch2_pass = client.patch(
        f"/console/incidents/{inc_id}",
        json={"status": "RESOLVED", "resolution_notes": "Identified employee error; policy updated."},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert patch2_pass.status_code == 200
    assert patch2_pass.json()["status"] == "RESOLVED"
    assert patch2_pass.json()["resolved_at"] is not None

    # 4. RESOLVED -> CLOSED
    patch3 = client.patch(
        f"/console/incidents/{inc_id}",
        json={"status": "CLOSED"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert patch3.status_code == 200
    assert patch3.json()["status"] == "CLOSED"


def test_invalid_status_transition_rejected(client, db_session):
    hr_owner = db_session.query(User).filter_by(email="hr_owner@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Payroll Data").first()
    token = session_token(db_session, subject=hr_owner.id)

    inc_resp = client.post(
        "/console/incidents",
        json={"title": "Invalid Step Test", "description": "Test", "severity": "LOW", "resource_id": res.id},
        headers={"Authorization": f"Bearer {token}"},
    )
    inc_id = inc_resp.json()["id"]

    # OPEN -> CLOSED (Invalid backward/skip transition)
    resp = client.patch(
        f"/console/incidents/{inc_id}",
        json={"status": "CLOSED"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 400
    assert "Invalid status transition" in resp.json()["detail"]


def test_attach_security_events_and_prevent_duplicates(client, db_session):
    hr_owner = db_session.query(User).filter_by(email="hr_owner@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Payroll Data").first()
    token = session_token(db_session, subject=hr_owner.id)

    sec_event = SecurityEvent(
        event_type="CRITICAL_RESOURCE_ACCESS",
        severity="CRITICAL",
        resource_id=res.id,
        description="Manual test security event",
    )
    db_session.add(sec_event)
    db_session.commit()

    inc_resp = client.post(
        "/console/incidents",
        json={"title": "Event Link Test", "description": "Test", "severity": "HIGH", "resource_id": res.id},
        headers={"Authorization": f"Bearer {token}"},
    )
    inc_id = inc_resp.json()["id"]

    # Attach event
    attach_resp = client.post(
        f"/console/incidents/{inc_id}/events",
        json={"security_event_ids": [sec_event.id]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert attach_resp.status_code == 200
    assert len(attach_resp.json()["security_events"]) == 1

    # Re-attach same event (duplicate prevention)
    attach_resp2 = client.post(
        f"/console/incidents/{inc_id}/events",
        json={"security_event_ids": [sec_event.id]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert len(attach_resp2.json()["security_events"]) == 1


def test_automatic_incident_escalation_on_high_severity_event(client, db_session):
    eng_user = db_session.query(User).filter_by(email="eng_req@gnosis.com").first()
    crit_res = db_session.query(Resource).filter_by(name="Master Keys").first()
    token = session_token(db_session, subject=eng_user.id)

    # Accessing CRITICAL resource produces CRITICAL SecurityEvent
    client.get(f"/resources/{crit_res.id}", headers={"Authorization": f"Bearer {token}"})

    # Verify Incident automatically created
    incidents = db_session.query(Incident).filter(Incident.resource_id == crit_res.id).all()
    assert len(incidents) == 1
    assert incidents[0].severity == "CRITICAL"
    assert incidents[0].status == "OPEN"


def test_multiple_high_events_do_not_create_duplicate_incidents(client, db_session):
    eng_user = db_session.query(User).filter_by(email="eng_req@gnosis.com").first()
    crit_res = db_session.query(Resource).filter_by(name="Master Keys").first()
    token = session_token(db_session, subject=eng_user.id)

    # Two qualifying requests in the same bounded detection episode.
    client.get(f"/resources/{crit_res.id}", headers={"Authorization": f"Bearer {token}"})
    client.get(f"/resources/{crit_res.id}", headers={"Authorization": f"Bearer {token}"})

    incidents = db_session.query(Incident).filter(Incident.resource_id == crit_res.id).all()
    assert len(incidents) == 1  # Reuses existing OPEN incident

    inc_events = db_session.query(IncidentEvent).filter(IncidentEvent.incident_id == incidents[0].id).all()
    assert len(inc_events) == 1  # Stage 2 deduplicates the episode and its evidence link.


def test_deleting_incident_preserves_security_event(db_session):
    res = db_session.query(Resource).filter_by(name="HR Payroll Data").first()

    sec_event = SecurityEvent(
        event_type="TEST_EVENT",
        severity="MEDIUM",
        resource_id=res.id,
        description="Preservation test",
    )
    db_session.add(sec_event)
    db_session.commit()

    inc = Incident(
        title="Deletion Test",
        description="Test",
        severity="MEDIUM",
        status="OPEN",
        resource_id=res.id,
    )
    db_session.add(inc)
    db_session.commit()

    inc_event = IncidentEvent(incident_id=inc.id, security_event_id=sec_event.id)
    db_session.add(inc_event)
    db_session.commit()

    # Delete Incident
    db_session.delete(inc)
    db_session.commit()

    # SecurityEvent must still exist
    retained_sec_event = db_session.query(SecurityEvent).filter_by(id=sec_event.id).first()
    assert retained_sec_event is not None


def test_dashboard_summary_scope(client, db_session):
    hr_owner = db_session.query(User).filter_by(email="hr_owner@gnosis.com").first()
    eng_user = db_session.query(User).filter_by(email="eng_req@gnosis.com").first()
    token_owner = session_token(db_session, subject=hr_owner.id)
    token_eng = session_token(db_session, subject=eng_user.id)

    # Owner summary
    resp_owner = client.get("/console/dashboard/summary", headers={"Authorization": f"Bearer {token_owner}"})
    assert resp_owner.status_code == 200

    # Eng summary
    resp_eng = client.get("/console/dashboard/summary", headers={"Authorization": f"Bearer {token_eng}"})
    assert resp_eng.status_code == 200
