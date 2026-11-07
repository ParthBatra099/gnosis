from datetime import datetime, timedelta, timezone
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base, get_db
from app.core.security import create_access_token, hash_password
from app.main import app
from app.models.access_grant import AccessGrant
from app.models.access_request import AccessRequest
from app.models.department import Department
from app.models.resource import Resource
from app.models.user import User


@pytest.mark.parametrize("state,expected", [
    ("non_expiring", 400), ("future", 400), ("expired", 201),
    ("revoked", 201), ("exact_expiry", 201), ("mixed", 400),
])
def test_request_checks_only_active_grants(client, db_session, state, expected):
    user = db_session.query(User).filter_by(email="eng_emp@gnosis.com").one()
    resource = db_session.query(Resource).filter_by(name="HR Payroll File").one()
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    grant = AccessGrant(user_id=user.id, resource_id=resource.id, permission="read")
    if state in {"expired", "mixed"}:
        grant.expires_at = now - timedelta(seconds=1)
    elif state == "future":
        grant.expires_at = now + timedelta(days=1)
    elif state == "exact_expiry":
        grant.expires_at = now
    elif state == "revoked":
        grant.revoked_at = now - timedelta(seconds=1)
    db_session.add(grant)
    if state == "mixed":
        db_session.add(AccessGrant(user_id=user.id, resource_id=resource.id, permission="read"))
    db_session.commit()
    original_grant_id = grant.id
    token = create_access_token(subject=user.id)
    with patch("app.api.v1.access.datetime", wraps=datetime) as clock:
        clock.now.return_value = now
        response = client.post("/access/requests", json={
            "resource_id": resource.id, "permission": "read", "reason": "Renew access",
        }, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == expected
    assert db_session.get(AccessGrant, original_grant_id) is not None


@pytest.fixture
def db_session():
    """Isolated SQLite in-memory DB for access request tests."""
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
    hr_user = User(
        name="HR Employee",
        email="hr_emp@gnosis.com",
        password_hash=hash_password("Pass123!"),
        role="EMPLOYEE",
        department_id=hr_dept.id,
        active=True,
    )
    eng_user = User(
        name="Eng Employee",
        email="eng_emp@gnosis.com",
        password_hash=hash_password("Pass123!"),
        role="EMPLOYEE",
        department_id=eng_dept.id,
        active=True,
    )
    session.add_all([hr_user, eng_user])
    session.commit()

    # Seed resources
    hr_res = Resource(
        name="HR Payroll File",
        description="Salary ledger",
        department_id=hr_dept.id,
        owner_id=hr_user.id,
        sensitivity="INTERNAL",
    )
    session.add(hr_res)
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


def test_create_access_request_success(client, db_session):
    eng_user = db_session.query(User).filter_by(email="eng_emp@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Payroll File").first()
    token = create_access_token(subject=eng_user.id)

    response = client.post(
        "/access/requests",
        json={
            "resource_id": res.id,
            "permission": "read",
            "reason": "Auditing project budget requirements",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["requester_id"] == eng_user.id
    assert data["resource_id"] == res.id
    assert data["permission"] == "read"
    assert data["status"] == "PENDING"


def test_create_access_request_already_authorized(client, db_session):
    """
    An explicit active AccessGrant blocks duplicate request creation.
    Policy-based ALLOW does not block requests, but an explicit grant does.
    """
    hr_user = db_session.query(User).filter_by(email="hr_emp@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Payroll File").first()
    token = create_access_token(subject=hr_user.id)

    # Seed explicit grant
    grant = AccessGrant(
        user_id=hr_user.id,
        resource_id=res.id,
        permission="read",
        granted_by=hr_user.id,
    )
    db_session.add(grant)
    db_session.commit()

    response = client.post(
        "/access/requests",
        json={
            "resource_id": res.id,
            "permission": "read",
            "reason": "Unnecessary request",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Access already granted for this resource and permission"


def test_create_access_request_duplicate_pending(client, db_session):
    eng_user = db_session.query(User).filter_by(email="eng_emp@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Payroll File").first()
    token = create_access_token(subject=eng_user.id)

    # First submission -> Success
    resp1 = client.post(
        "/access/requests",
        json={"resource_id": res.id, "permission": "read", "reason": "First request"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp1.status_code == 201

    # Second submission -> Conflict
    resp2 = client.post(
        "/access/requests",
        json={"resource_id": res.id, "permission": "read", "reason": "Duplicate request"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp2.status_code == 409
    assert resp2.json()["detail"] == "A pending access request for this resource and permission already exists"


def test_create_access_request_unsupported_permission(client, db_session):
    eng_user = db_session.query(User).filter_by(email="eng_emp@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Payroll File").first()
    token = create_access_token(subject=eng_user.id)

    response = client.post(
        "/access/requests",
        json={"resource_id": res.id, "permission": "execute_code", "reason": "Testing invalid permission"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 400
    assert "Unsupported permission" in response.json()["detail"]


def test_create_access_request_missing_resource(client, db_session):
    eng_user = db_session.query(User).filter_by(email="eng_emp@gnosis.com").first()
    token = create_access_token(subject=eng_user.id)

    response = client.post(
        "/access/requests",
        json={"resource_id": "nonexistent-id-9999", "permission": "read", "reason": "Testing missing resource"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404


def test_create_access_request_unauthenticated(client, db_session):
    res = db_session.query(Resource).filter_by(name="HR Payroll File").first()

    response = client.post(
        "/access/requests",
        json={"resource_id": res.id, "permission": "read", "reason": "No auth token"},
    )
    assert response.status_code == 401


def test_get_my_access_requests_history(client, db_session):
    eng_user = db_session.query(User).filter_by(email="eng_emp@gnosis.com").first()
    hr_user = db_session.query(User).filter_by(email="hr_emp@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Payroll File").first()

    eng_token = create_access_token(subject=eng_user.id)
    hr_token = create_access_token(subject=hr_user.id)

    # Submit request as eng_user
    client.post(
        "/access/requests",
        json={"resource_id": res.id, "permission": "read", "reason": "Engineering audit"},
        headers={"Authorization": f"Bearer {eng_token}"},
    )

    # Eng user sees 1 request
    eng_resp = client.get("/access/requests/me", headers={"Authorization": f"Bearer {eng_token}"})
    assert eng_resp.status_code == 200
    assert len(eng_resp.json()) == 1

    # HR user sees 0 requests
    hr_resp = client.get("/access/requests/me", headers={"Authorization": f"Bearer {hr_token}"})
    assert hr_resp.status_code == 200
    assert len(hr_resp.json()) == 0