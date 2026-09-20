from datetime import datetime, timezone
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base, get_db
from app.core.security import create_access_token, hash_password
from app.main import app
from app.models.department import Department
from app.models.resource import Resource
from app.models.user import User


@pytest.fixture
def db_session():
    """Isolated SQLite in-memory DB for Phase 3 audit and detection tests."""
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
        department_id=hr_dept.id,
        active=True,
    )
    eng_user = User(
        name="Eng Requester",
        email="eng_req@gnosis.com",
        password_hash=hash_password("Pass123!"),
        role="EMPLOYEE",
        department_id=eng_dept.id,
        active=True,
    )
    session.add_all([hr_owner, eng_user])
    session.commit()

    # Seed resources
    hr_res = Resource(
        name="HR Payroll Data",
        description="Payroll details",
        department_id=hr_dept.id,
        owner_id=hr_owner.id,
        sensitivity="INTERNAL",
    )
    critical_res = Resource(
        name="Master Keys",
        description="Encryption keys",
        department_id=hr_dept.id,
        owner_id=hr_owner.id,
        sensitivity="CRITICAL",
    )
    eng_res = Resource(
        name="Engineering Docs",
        description="Specs",
        department_id=eng_dept.id,
        owner_id=hr_owner.id,
        sensitivity="INTERNAL",
    )
    session.add_all([hr_res, critical_res, eng_res])
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
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def test_login_creates_audit_event(client, db_session):
    resp = client.post(
        "/auth/login",
        json={"email": "eng_req@gnosis.com", "password": "Pass123!"},
    )
    assert resp.status_code == 200
    token = resp.json()["access_token"]

    logs_resp = client.get("/monitoring/audit-logs", headers={"Authorization": f"Bearer {token}"})
    assert logs_resp.status_code == 200
    logs = logs_resp.json()
    assert len(logs) == 1
    assert logs[0]["action"] == "LOGIN"
    assert logs[0]["outcome"] == "ALLOW"


def test_resource_access_creates_audit_event(client, db_session):
    user = db_session.query(User).filter_by(email="hr_owner@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Payroll Data").first()
    token = create_access_token(subject=user.id)

    # Allowed access
    resp = client.get(f"/resources/{res.id}", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200

    logs_resp = client.get("/monitoring/audit-logs", headers={"Authorization": f"Bearer {token}"})
    logs = logs_resp.json()
    assert len(logs) == 1
    assert logs[0]["action"] == "RESOURCE_ACCESS"
    assert logs[0]["outcome"] == "ALLOW"


def test_access_request_lifecycle_audited(client, db_session):
    eng_user = db_session.query(User).filter_by(email="eng_req@gnosis.com").first()
    hr_owner = db_session.query(User).filter_by(email="hr_owner@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Payroll Data").first()

    eng_token = create_access_token(subject=eng_user.id)
    owner_token = create_access_token(subject=hr_owner.id)

    # 1. Create request
    req_resp = client.post(
        "/access/requests",
        json={"resource_id": res.id, "permission": "read", "reason": "Audit request"},
        headers={"Authorization": f"Bearer {eng_token}"},
    )
    assert req_resp.status_code == 201
    req_id = req_resp.json()["id"]

    # 2. Approve request
    app_resp = client.post(
        f"/access/requests/{req_id}/approve",
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert app_resp.status_code == 200
    grant_id = app_resp.json()["id"]

    # 3. Revoke grant
    rev_resp = client.post(
        f"/access/grants/{grant_id}/revoke",
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert rev_resp.status_code == 200

    # Verify audit logs for owner
    logs_resp = client.get("/monitoring/audit-logs", headers={"Authorization": f"Bearer {owner_token}"})
    actions = [l["action"] for l in logs_resp.json()]
    assert "ACCESS_REQUEST_CREATED" in actions
    assert "ACCESS_REQUEST_APPROVED" in actions
    assert "GRANT_REVOKED" in actions


def test_detection_repeated_denied_access(client, db_session):
    eng_user = db_session.query(User).filter_by(email="eng_req@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Payroll Data").first()
    token = create_access_token(subject=eng_user.id)

    # Trigger 3 cross-department access denials
    for _ in range(3):
        client.get(f"/resources/{res.id}", headers={"Authorization": f"Bearer {token}"})

    sec_resp = client.get("/monitoring/security-events", headers={"Authorization": f"Bearer {token}"})
    assert sec_resp.status_code == 200
    sec_events = sec_resp.json()
    assert any(e["event_type"] == "REPEATED_DENIED_ACCESS" and e["severity"] == "HIGH" for e in sec_events)


def test_detection_critical_resource_access(client, db_session):
    eng_user = db_session.query(User).filter_by(email="eng_req@gnosis.com").first()
    crit_res = db_session.query(Resource).filter_by(name="Master Keys").first()
    token = create_access_token(subject=eng_user.id)

    # Denied attempt on CRITICAL resource
    client.get(f"/resources/{crit_res.id}", headers={"Authorization": f"Bearer {token}"})

    sec_resp = client.get("/monitoring/security-events", headers={"Authorization": f"Bearer {token}"})
    sec_events = sec_resp.json()
    assert any(e["event_type"] == "CRITICAL_RESOURCE_ACCESS" and e["severity"] == "CRITICAL" for e in sec_events)


def test_detection_cross_department_anomaly(client, db_session):
    eng_user = db_session.query(User).filter_by(email="eng_req@gnosis.com").first()
    res1 = db_session.query(Resource).filter_by(name="HR Payroll Data").first()
    res2 = db_session.query(Resource).filter_by(name="Master Keys").first()
    token = create_access_token(subject=eng_user.id)

    # Probing 2 distinct cross-department resources
    client.get(f"/resources/{res1.id}", headers={"Authorization": f"Bearer {token}"})
    client.get(f"/resources/{res2.id}", headers={"Authorization": f"Bearer {token}"})

    sec_resp = client.get("/monitoring/security-events", headers={"Authorization": f"Bearer {token}"})
    sec_events = sec_resp.json()
    assert any(e["event_type"] == "CROSS_DEPARTMENT_ANOMALY" and e["severity"] == "HIGH" for e in sec_events)


def test_detection_after_hours_access(client, db_session):
    user = db_session.query(User).filter_by(email="hr_owner@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Payroll Data").first()
    token = create_access_token(subject=user.id)

    after_hours_time = datetime(2026, 9, 20, 23, 0, 0, tzinfo=timezone.utc)
    with patch("app.models.audit_event.datetime") as mock_datetime:
        mock_datetime.now.return_value = after_hours_time
        client.get(f"/resources/{res.id}", headers={"Authorization": f"Bearer {token}"})

    sec_resp = client.get("/monitoring/security-events", headers={"Authorization": f"Bearer {token}"})
    sec_events = sec_resp.json()
    assert any(e["event_type"] == "AFTER_HOURS_ACCESS" and e["severity"] == "LOW" for e in sec_events)


def test_audit_failure_does_not_break_authorization(client, db_session):
    user = db_session.query(User).filter_by(email="hr_owner@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Payroll Data").first()
    token = create_access_token(subject=user.id)

    with patch("app.services.audit_service.record_audit_event", side_effect=Exception("Database connection loss")):
        resp = client.get(f"/resources/{res.id}", headers={"Authorization": f"Bearer {token}"})
        # Authorization decision MUST remain ALLOW (200) despite audit failure
        assert resp.status_code == 200
        assert resp.json()["id"] == res.id