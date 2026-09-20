import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base, get_db
from app.core.security import create_access_token, hash_password
from app.main import app
from app.models.audit_event import AuditEvent
from app.models.department import Department
from app.models.incident import Incident
from app.models.resource import Resource
from app.models.security_event import SecurityEvent
from app.models.user import User


@pytest.fixture
def db_session():
    """Isolated SQLite in-memory DB for Phase 5A AI Investigator tests."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()

    # Seed department
    dept = Department(name="Security")
    session.add(dept)
    session.commit()

    # Seed users
    owner = User(
        name="Owner User",
        email="owner@gnosis.com",
        password_hash=hash_password("Pass123!"),
        role="EMPLOYEE",
        department_id=dept.id,
        active=True,
    )
    unauth_user = User(
        name="Unauth User",
        email="unauth@gnosis.com",
        password_hash=hash_password("Pass123!"),
        role="EMPLOYEE",
        department_id=dept.id,
        active=True,
    )
    session.add_all([owner, unauth_user])
    session.commit()

    # Seed resource owned by owner
    res = Resource(
        name="Secure Vault",
        description="Secrets Vault",
        department_id=dept.id,
        owner_id=owner.id,
        sensitivity="CRITICAL",
    )
    session.add(res)
    session.commit()

    # Seed security event, audit event, and incident
    sec_event = SecurityEvent(
        event_type="CRITICAL_RESOURCE_ACCESS",
        severity="CRITICAL",
        resource_id=res.id,
        description="Unauthorized vault access attempt",
    )
    audit_event = AuditEvent(
        actor_id=unauth_user.id,
        action="RESOURCE_ACCESS",
        resource_id=res.id,
        outcome="DENY",
        reason="DENY_DEPARTMENT_MISMATCH",
    )
    inc = Incident(
        title="Vault Intrusion Alert",
        description="Critical vault intrusion detected",
        severity="CRITICAL",
        status="OPEN",
        resource_id=res.id,
    )
    session.add_all([sec_event, audit_event, inc])
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
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    app.dependency_overrides.clear()


def test_unauthenticated_request_returns_401(client):
    """1. Unauthenticated investigation request must return 401 Unauthorized."""
    resp = client.post("/ai/investigate", json={"question": "Why was access denied?"})
    assert resp.status_code == 401


def test_authenticated_investigator_request_succeeds(client, db_session):
    """2. Authenticated request succeeds with HTTP 200."""
    owner = db_session.query(User).filter_by(email="owner@gnosis.com").first()
    token = create_access_token(subject=owner.id)

    resp = client.post(
        "/ai/investigate",
        json={"question": "Why was access denied?"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["intent"] == "ACCESS_DENIAL_ANALYSIS"


def test_supported_intents_detected(client, db_session):
    """3. Supported intents (access denial, security activity, incidents) are correctly parsed."""
    owner = db_session.query(User).filter_by(email="owner@gnosis.com").first()
    token = create_access_token(subject=owner.id)

    r1 = client.post(
        "/ai/investigate",
        json={"question": "Why was my permission blocked?"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r1.status_code == 200
    assert r1.json()["intent"] == "ACCESS_DENIAL_ANALYSIS"

    r2 = client.post(
        "/ai/investigate",
        json={"question": "Show me recent security activity and events"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r2.status_code == 200
    assert r2.json()["intent"] == "SECURITY_ACTIVITY"

    r3 = client.post(
        "/ai/investigate",
        json={"question": "Investigate open incident cases"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r3.status_code == 200
    assert r3.json()["intent"] == "INCIDENT_INVESTIGATION"


def test_unsupported_question_returns_structured_unknown_intent(client, db_session):
    """4. Questions outside known intents return a structured UNKNOWN intent response."""
    owner = db_session.query(User).filter_by(email="owner@gnosis.com").first()
    token = create_access_token(subject=owner.id)

    resp = client.post(
        "/ai/investigate",
        json={"question": "What is the weather today?"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["intent"] == "UNKNOWN"
    assert data["risk_level"] == "LOW"
    assert len(data["evidence"]) == 0


def test_security_event_evidence_retrieved_for_authorized_owner(client, db_session):
    """5. Security event evidence is retrieved for authorized resource owners."""
    owner = db_session.query(User).filter_by(email="owner@gnosis.com").first()
    token = create_access_token(subject=owner.id)

    resp = client.post(
        "/ai/investigate",
        json={"question": "Show recent security events"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["evidence"]) == 1
    assert data["evidence"][0]["source_type"] == "security_event"


def test_incident_evidence_retrieved(client, db_session):
    """6. Incident evidence is retrieved when authorized."""
    owner = db_session.query(User).filter_by(email="owner@gnosis.com").first()
    inc = db_session.query(Incident).first()
    token = create_access_token(subject=owner.id)

    resp = client.post(
        "/ai/investigate",
        json={"question": "Investigate incident", "incident_id": inc.id},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["evidence"]) == 1
    assert data["evidence"][0]["source_type"] == "incident"
    assert data["evidence"][0]["source_id"] == inc.id


def test_unauthorized_security_event_not_exposed(client, db_session):
    """7. Unauthorized users cannot retrieve security events for unowned resources."""
    unauth = db_session.query(User).filter_by(email="unauth@gnosis.com").first()
    token = create_access_token(subject=unauth.id)

    resp = client.post(
        "/ai/investigate",
        json={"question": "Show security activity"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert len(resp.json()["evidence"]) == 0


def test_unauthorized_incident_not_exposed(client, db_session):
    """8. Unauthorized users cannot retrieve incidents for unowned resources."""
    unauth = db_session.query(User).filter_by(email="unauth@gnosis.com").first()
    inc = db_session.query(Incident).first()
    token = create_access_token(subject=unauth.id)

    resp = client.post(
        "/ai/investigate",
        json={"question": "Investigate incident", "incident_id": inc.id},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert len(resp.json()["evidence"]) == 0


def test_investigator_performs_no_database_writes(client, db_session):
    """9. The investigator is strictly read-only and mutates zero database rows."""
    owner = db_session.query(User).filter_by(email="owner@gnosis.com").first()
    token = create_access_token(subject=owner.id)

    audit_count_before = db_session.query(AuditEvent).count()
    sec_count_before = db_session.query(SecurityEvent).count()
    inc_count_before = db_session.query(Incident).count()

    client.post(
        "/ai/investigate",
        json={"question": "Why was access denied?"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert db_session.query(AuditEvent).count() == audit_count_before
    assert db_session.query(SecurityEvent).count() == sec_count_before
    assert db_session.query(Incident).count() == inc_count_before


def test_nonexistent_incident_id_returns_neutral_response(client, db_session):
    """10. Nonexistent incident_id returns a neutral response without leaking details or raising 500."""
    owner = db_session.query(User).filter_by(email="owner@gnosis.com").first()
    token = create_access_token(subject=owner.id)

    resp = client.post(
        "/ai/investigate",
        json={"question": "Investigate incident", "incident_id": "00000000-0000-0000-0000-000000000000"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["intent"] == "INCIDENT_INVESTIGATION"
    assert data["risk_level"] == "LOW"
    assert len(data["evidence"]) == 0
    assert data["summary"] == "No authorized incidents found matching the request criteria."