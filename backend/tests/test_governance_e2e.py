import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base, get_db
from app.core.security import hash_password
from app.main import app
from app.models.department import Department
from app.models.resource import Resource
from app.models.user import User


@pytest.fixture
def db_session():
    """Isolated SQLite in-memory DB for E2E governance integration tests."""
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

    # Seed users with known passwords for POST /auth/login testing
    hr_owner = User(
        name="HR Resource Owner",
        email="hr_owner@gnosis.com",
        password_hash=hash_password("OwnerPassword123!"),
        role="EMPLOYEE",
        department_id=hr_dept.id,
        active=True,
    )
    eng_user = User(
        name="Engineering Employee",
        email="eng_emp@gnosis.com",
        password_hash=hash_password("EmployeePassword123!"),
        role="EMPLOYEE",
        department_id=eng_dept.id,
        active=True,
    )
    session.add_all([hr_owner, eng_user])
    session.commit()

    # Seed cross-department resource owned by hr_owner
    hr_resource = Resource(
        name="HR Salary Data",
        description="Confidential HR Compensation Data",
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


def test_e2e_full_access_governance_lifecycle(client, db_session):
    # 1. Employee login via POST /auth/login
    emp_login_resp = client.post(
        "/auth/login",
        json={"email": "eng_emp@gnosis.com", "password": "EmployeePassword123!"},
    )
    assert emp_login_resp.status_code == 200
    token_emp = emp_login_resp.json()["access_token"]
    headers_emp = {"Authorization": f"Bearer {token_emp}"}

    # Fetch resource ID
    res = db_session.query(Resource).filter_by(name="HR Salary Data").first()

    # 2. Unauthorized cross-department resource access attempt (403)
    access_denied_resp = client.get(f"/resources/{res.id}", headers=headers_emp)
    assert access_denied_resp.status_code == 403
    assert access_denied_resp.json()["detail"]["reason"] == "DENY_DEPARTMENT_MISMATCH"

    # 3. Submit access request (201)
    req_resp = client.post(
        "/access/requests",
        json={
            "resource_id": res.id,
            "permission": "read",
            "reason": "Auditing project budget requirements",
        },
        headers=headers_emp,
    )
    assert req_resp.status_code == 201
    request_data = req_resp.json()
    assert request_data["status"] == "PENDING"
    request_id = request_data["id"]

    # 4. Resource Owner login via POST /auth/login
    owner_login_resp = client.post(
        "/auth/login",
        json={"email": "hr_owner@gnosis.com", "password": "OwnerPassword123!"},
    )
    assert owner_login_resp.status_code == 200
    token_owner = owner_login_resp.json()["access_token"]
    headers_owner = {"Authorization": f"Bearer {token_owner}"}

    # 5. Owner views pending requests
    pending_resp = client.get("/access/requests/pending-approvals", headers=headers_owner)
    assert pending_resp.status_code == 200
    pending_requests = pending_resp.json()
    assert len(pending_requests) == 1
    assert pending_requests[0]["id"] == request_id

    # 6. Non-owner attempts approval (403)
    unauthorized_approve_resp = client.post(
        f"/access/requests/{request_id}/approve",
        json={"expires_at": None},
        headers=headers_emp,
    )
    assert unauthorized_approve_resp.status_code == 403

    # 7. Owner approves request (200) -> Returns AccessGrant
    approve_resp = client.post(
        f"/access/requests/{request_id}/approve",
        json={"expires_at": None},
        headers=headers_owner,
    )
    assert approve_resp.status_code == 200
    grant_data = approve_resp.json()
    assert grant_data["access_request_id"] == request_id
    assert grant_data["permission"] == "read"
    grant_id = grant_data["id"]

    # 8. Employee accesses resource (200)
    authorized_access_resp = client.get(f"/resources/{res.id}", headers=headers_emp)
    assert authorized_access_resp.status_code == 200
    assert authorized_access_resp.json()["id"] == res.id

    # 9. Employee checks /access/grants/me
    emp_grants_resp = client.get("/access/grants/me", headers=headers_emp)
    assert emp_grants_resp.status_code == 200
    emp_grants = emp_grants_resp.json()
    assert len(emp_grants) == 1
    assert emp_grants[0]["id"] == grant_id

    # 10. Owner checks /access/grants/owned
    owner_grants_resp = client.get("/access/grants/owned", headers=headers_owner)
    assert owner_grants_resp.status_code == 200
    owner_grants = owner_grants_resp.json()
    assert len(owner_grants) == 1
    assert owner_grants[0]["id"] == grant_id

    # 11. Owner revokes grant (200)
    revoke_resp = client.post(f"/access/grants/{grant_id}/revoke", headers=headers_owner)
    assert revoke_resp.status_code == 200
    revoked_grant_data = revoke_resp.json()
    assert revoked_grant_data["revoked_at"] is not None
    assert revoked_grant_data["revoked_by"] is not None

    # 12. Employee attempts access again (403) -> falls back to DENY_DEPARTMENT_MISMATCH
    post_revoke_access_resp = client.get(f"/resources/{res.id}", headers=headers_emp)
    assert post_revoke_access_resp.status_code == 403
    assert post_revoke_access_resp.json()["detail"]["reason"] == "DENY_DEPARTMENT_MISMATCH"

    # 13. Verify revoked grant still exists in employee grant history with populated metadata
    history_resp = client.get("/access/grants/me", headers=headers_emp)
    assert history_resp.status_code == 200
    history_grants = history_resp.json()
    assert len(history_grants) == 1
    assert history_grants[0]["id"] == grant_id
    assert history_grants[0]["revoked_at"] is not None
    assert history_grants[0]["revoked_by"] == revoked_grant_data["revoked_by"]


def test_e2e_access_rejection_workflow(client, db_session):
    # 1. Employee login via POST /auth/login
    emp_login_resp = client.post(
        "/auth/login",
        json={"email": "eng_emp@gnosis.com", "password": "EmployeePassword123!"},
    )
    assert emp_login_resp.status_code == 200
    token_emp = emp_login_resp.json()["access_token"]
    headers_emp = {"Authorization": f"Bearer {token_emp}"}

    res = db_session.query(Resource).filter_by(name="HR Salary Data").first()

    # 2. Submit cross-department access request
    req_resp = client.post(
        "/access/requests",
        json={
            "resource_id": res.id,
            "permission": "read",
            "reason": "Request to be rejected",
        },
        headers=headers_emp,
    )
    assert req_resp.status_code == 201
    request_id = req_resp.json()["id"]

    # 3. Owner login via POST /auth/login
    owner_login_resp = client.post(
        "/auth/login",
        json={"email": "hr_owner@gnosis.com", "password": "OwnerPassword123!"},
    )
    assert owner_login_resp.status_code == 200
    token_owner = owner_login_resp.json()["access_token"]
    headers_owner = {"Authorization": f"Bearer {token_owner}"}

    # 4. Owner sees pending request
    pending_resp = client.get("/access/requests/pending-approvals", headers=headers_owner)
    assert pending_resp.status_code == 200
    assert len(pending_resp.json()) == 1

    # 5. Owner rejects request
    reject_resp = client.post(
        f"/access/requests/{request_id}/reject",
        headers=headers_owner,
    )
    assert reject_resp.status_code == 200
    assert reject_resp.json()["status"] == "REJECTED"

    # 6. Employee remains denied
    access_resp = client.get(f"/resources/{res.id}", headers=headers_emp)
    assert access_resp.status_code == 403

    # 7. Employee grant history contains no grant for the rejected request
    grants_resp = client.get("/access/grants/me", headers=headers_emp)
    assert grants_resp.status_code == 200
    assert len(grants_resp.json()) == 0

    # 8. Employee request history shows REJECTED status
    requests_history_resp = client.get("/access/requests/me", headers=headers_emp)
    assert requests_history_resp.status_code == 200
    history = requests_history_resp.json()
    assert len(history) == 1
    assert history[0]["id"] == request_id
    assert history[0]["status"] == "REJECTED"