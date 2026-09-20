from datetime import datetime, timedelta, timezone
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
from app.security.access_decision import evaluate_access


@pytest.fixture
def db_session():
    """Isolated SQLite in-memory DB for grant expiration and revocation tests."""
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

    # Seed cross-department resource
    hr_resource = Resource(
        name="HR Ledger",
        description="Confidential HR Ledger",
        department_id=hr_dept.id,
        owner_id=hr_owner.id,
        sensitivity="CONFIDENTIAL",
    )
    session.add(hr_resource)
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


def test_active_non_expiring_grant_allows_access(client, db_session):
    eng_user = db_session.query(User).filter_by(email="eng_req@gnosis.com").first()
    hr_owner = db_session.query(User).filter_by(email="hr_owner@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Ledger").first()

    grant = AccessGrant(
        user_id=eng_user.id,
        resource_id=res.id,
        permission="read",
        granted_by=hr_owner.id,
        expires_at=None,
    )
    db_session.add(grant)
    db_session.commit()

    token = create_access_token(subject=eng_user.id)
    response = client.get(f"/resources/{res.id}", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200


def test_future_expiring_grant_allows_access(client, db_session):
    eng_user = db_session.query(User).filter_by(email="eng_req@gnosis.com").first()
    hr_owner = db_session.query(User).filter_by(email="hr_owner@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Ledger").first()

    future_exp = datetime.now(timezone.utc) + timedelta(hours=2)
    grant = AccessGrant(
        user_id=eng_user.id,
        resource_id=res.id,
        permission="read",
        granted_by=hr_owner.id,
        expires_at=future_exp,
    )
    db_session.add(grant)
    db_session.commit()

    token = create_access_token(subject=eng_user.id)
    response = client.get(f"/resources/{res.id}", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200


def test_expired_cross_department_grant_denies_access(client, db_session):
    eng_user = db_session.query(User).filter_by(email="eng_req@gnosis.com").first()
    hr_owner = db_session.query(User).filter_by(email="hr_owner@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Ledger").first()

    past_exp = datetime.now(timezone.utc) - timedelta(minutes=10)
    grant = AccessGrant(
        user_id=eng_user.id,
        resource_id=res.id,
        permission="read",
        granted_by=hr_owner.id,
        expires_at=past_exp,
    )
    db_session.add(grant)
    db_session.commit()

    token = create_access_token(subject=eng_user.id)
    response = client.get(f"/resources/{res.id}", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403
    assert response.json()["detail"]["reason"] == "DENY_DEPARTMENT_MISMATCH"


def test_revoked_grant_denies_access(client, db_session):
    eng_user = db_session.query(User).filter_by(email="eng_req@gnosis.com").first()
    hr_owner = db_session.query(User).filter_by(email="hr_owner@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Ledger").first()

    grant = AccessGrant(
        user_id=eng_user.id,
        resource_id=res.id,
        permission="read",
        granted_by=hr_owner.id,
        revoked_at=datetime.now(timezone.utc),
        revoked_by=hr_owner.id,
    )
    db_session.add(grant)
    db_session.commit()

    token = create_access_token(subject=eng_user.id)
    response = client.get(f"/resources/{res.id}", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403
    assert response.json()["detail"]["reason"] == "DENY_DEPARTMENT_MISMATCH"


def test_owner_can_revoke_grant(client, db_session):
    eng_user = db_session.query(User).filter_by(email="eng_req@gnosis.com").first()
    hr_owner = db_session.query(User).filter_by(email="hr_owner@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Ledger").first()

    grant = AccessGrant(
        user_id=eng_user.id,
        resource_id=res.id,
        permission="read",
        granted_by=hr_owner.id,
    )
    db_session.add(grant)
    db_session.commit()

    owner_token = create_access_token(subject=hr_owner.id)
    response = client.post(f"/access/grants/{grant.id}/revoke", headers={"Authorization": f"Bearer {owner_token}"})
    assert response.status_code == 200
    data = response.json()
    assert data["revoked_by"] == hr_owner.id
    assert data["revoked_at"] is not None

    # Database verification
    db_grant = db_session.query(AccessGrant).filter_by(id=grant.id).first()
    assert db_grant is not None
    assert db_grant.revoked_at is not None
    assert db_grant.revoked_by == hr_owner.id

    # Access revoked verification
    eng_token = create_access_token(subject=eng_user.id)
    access_resp = client.get(f"/resources/{res.id}", headers={"Authorization": f"Bearer {eng_token}"})
    assert access_resp.status_code == 403


def test_non_owner_cannot_revoke_grant(client, db_session):
    eng_user = db_session.query(User).filter_by(email="eng_req@gnosis.com").first()
    hr_owner = db_session.query(User).filter_by(email="hr_owner@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Ledger").first()

    grant = AccessGrant(
        user_id=eng_user.id,
        resource_id=res.id,
        permission="read",
        granted_by=hr_owner.id,
    )
    db_session.add(grant)
    db_session.commit()

    eng_token = create_access_token(subject=eng_user.id)
    response = client.post(f"/access/grants/{grant.id}/revoke", headers={"Authorization": f"Bearer {eng_token}"})
    assert response.status_code == 403


def test_already_revoked_grant_returns_400(client, db_session):
    eng_user = db_session.query(User).filter_by(email="eng_req@gnosis.com").first()
    hr_owner = db_session.query(User).filter_by(email="hr_owner@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Ledger").first()

    grant = AccessGrant(
        user_id=eng_user.id,
        resource_id=res.id,
        permission="read",
        granted_by=hr_owner.id,
        revoked_at=datetime.now(timezone.utc),
        revoked_by=hr_owner.id,
    )
    db_session.add(grant)
    db_session.commit()

    owner_token = create_access_token(subject=hr_owner.id)
    response = client.post(f"/access/grants/{grant.id}/revoke", headers={"Authorization": f"Bearer {owner_token}"})
    assert response.status_code == 400
    assert response.json()["detail"] == "Grant is already revoked"


def test_revoke_nonexistent_grant_returns_404(client, db_session):
    hr_owner = db_session.query(User).filter_by(email="hr_owner@gnosis.com").first()
    owner_token = create_access_token(subject=hr_owner.id)

    response = client.post("/access/grants/nonexistent-grant-id/revoke", headers={"Authorization": f"Bearer {owner_token}"})
    assert response.status_code == 404


def test_get_my_grants_history(client, db_session):
    eng_user = db_session.query(User).filter_by(email="eng_req@gnosis.com").first()
    hr_owner = db_session.query(User).filter_by(email="hr_owner@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Ledger").first()

    grant = AccessGrant(
        user_id=eng_user.id,
        resource_id=res.id,
        permission="read",
        granted_by=hr_owner.id,
    )
    db_session.add(grant)
    db_session.commit()

    eng_token = create_access_token(subject=eng_user.id)
    response = client.get("/access/grants/me", headers={"Authorization": f"Bearer {eng_token}"})
    assert response.status_code == 200
    grants = response.json()
    assert len(grants) == 1
    assert grants[0]["id"] == grant.id

    hr_token = create_access_token(subject=hr_owner.id)
    hr_grants = client.get("/access/grants/me", headers={"Authorization": f"Bearer {hr_token}"})
    assert len(hr_grants.json()) == 0


def test_get_owned_grants_history(client, db_session):
    eng_user = db_session.query(User).filter_by(email="eng_req@gnosis.com").first()
    hr_owner = db_session.query(User).filter_by(email="hr_owner@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Ledger").first()

    grant = AccessGrant(
        user_id=eng_user.id,
        resource_id=res.id,
        permission="read",
        granted_by=hr_owner.id,
    )
    db_session.add(grant)
    db_session.commit()

    owner_token = create_access_token(subject=hr_owner.id)
    response = client.get("/access/grants/owned", headers={"Authorization": f"Bearer {owner_token}"})
    assert response.status_code == 200
    grants = response.json()
    assert len(grants) == 1
    assert grants[0]["id"] == grant.id


def test_approval_with_expires_at(client, db_session):
    eng_user = db_session.query(User).filter_by(email="eng_req@gnosis.com").first()
    hr_owner = db_session.query(User).filter_by(email="hr_owner@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Ledger").first()

    req = AccessRequest(
        requester_id=eng_user.id,
        resource_id=res.id,
        permission="read",
        reason="Testing approval expires_at",
        status="PENDING",
    )
    db_session.add(req)
    db_session.commit()

    owner_token = create_access_token(subject=hr_owner.id)
    exp_time = "2026-09-25T12:00:00Z"
    response = client.post(
        f"/access/requests/{req.id}/approve",
        json={"expires_at": exp_time},
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert response.status_code == 200
    assert response.json()["expires_at"] is not None


def test_approval_with_null_expires_at(client, db_session):
    eng_user = db_session.query(User).filter_by(email="eng_req@gnosis.com").first()
    hr_owner = db_session.query(User).filter_by(email="hr_owner@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Ledger").first()

    req = AccessRequest(
        requester_id=eng_user.id,
        resource_id=res.id,
        permission="read",
        reason="Testing approval null expires_at",
        status="PENDING",
    )
    db_session.add(req)
    db_session.commit()

    owner_token = create_access_token(subject=hr_owner.id)
    response = client.post(
        f"/access/requests/{req.id}/approve",
        json={"expires_at": None},
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert response.status_code == 200
    assert response.json()["expires_at"] is None


def test_approval_with_past_expires_at_fails(client, db_session):
    eng_user = db_session.query(User).filter_by(email="eng_req@gnosis.com").first()
    hr_owner = db_session.query(User).filter_by(email="hr_owner@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Ledger").first()

    req = AccessRequest(
        requester_id=eng_user.id,
        resource_id=res.id,
        permission="read",
        reason="Testing past expires_at validation",
        status="PENDING",
    )
    db_session.add(req)
    db_session.commit()

    owner_token = create_access_token(subject=hr_owner.id)
    past_time = "2020-01-01T00:00:00Z"
    response = client.post(
        f"/access/requests/{req.id}/approve",
        json={"expires_at": past_time},
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "expires_at must be in the future"


def test_expired_same_department_grant_falls_through_to_allow(client, db_session):
    hr_dept = db_session.query(Department).filter_by(name="Human Resources").first()
    hr_owner = db_session.query(User).filter_by(email="hr_owner@gnosis.com").first()

    colleague = User(
        name="HR Colleague",
        email="hr_colleague@gnosis.com",
        password_hash=hash_password("Pass123!"),
        role="EMPLOYEE",
        department_id=hr_dept.id,
        active=True,
    )
    db_session.add(colleague)
    db_session.commit()

    res = db_session.query(Resource).filter_by(name="HR Ledger").first()

    past_exp = datetime.now(timezone.utc) - timedelta(minutes=10)
    grant = AccessGrant(
        user_id=colleague.id,
        resource_id=res.id,
        permission="read",
        granted_by=hr_owner.id,
        expires_at=past_exp,
    )
    db_session.add(grant)
    db_session.commit()

    token = create_access_token(subject=colleague.id)
    response = client.get(f"/resources/{res.id}", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["id"] == res.id


def test_exact_boundary_expiration(db_session):
    eng_user = db_session.query(User).filter_by(email="eng_req@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Ledger").first()

    now = datetime.now(timezone.utc)
    grant = AccessGrant(
        user_id=eng_user.id,
        resource_id=res.id,
        permission="read",
        expires_at=now,
    )

    decision = evaluate_access(
        user=eng_user,
        resource=res,
        requested_permission="read",
        active_grants=[grant],
    )
    assert decision.allowed is False
    assert decision.reason.value == "DENY_DEPARTMENT_MISMATCH"