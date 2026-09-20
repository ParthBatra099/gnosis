import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base, get_db
from app.core.security import create_access_token, hash_password
from app.main import app
from app.models.access_request import AccessRequest
from app.models.department import Department
from app.models.resource import Resource
from app.models.user import User


@pytest.fixture
def db_session():
    """Isolated SQLite in-memory DB for access grant and approval workflow tests."""
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

    # Seed cross-department resource owned by hr_owner
    hr_resource = Resource(
        name="HR Payroll Master",
        description="Confidential payroll",
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


def test_owner_approve_request_and_grant_access(client, db_session):
    hr_owner = db_session.query(User).filter_by(email="hr_owner@gnosis.com").first()
    eng_user = db_session.query(User).filter_by(email="eng_req@gnosis.com").first()
    resource = db_session.query(Resource).filter_by(name="HR Payroll Master").first()

    eng_token = create_access_token(subject=eng_user.id)
    owner_token = create_access_token(subject=hr_owner.id)

    # 1. Requester submits request
    req_resp = client.post(
        "/access/requests",
        json={"resource_id": resource.id, "permission": "read", "reason": "Cross-dept audit"},
        headers={"Authorization": f"Bearer {eng_token}"},
    )
    assert req_resp.status_code == 201
    request_id = req_resp.json()["id"]

    # 2. Before approval: Access to resource is DENIED
    access_before = client.get(
        f"/resources/{resource.id}",
        headers={"Authorization": f"Bearer {eng_token}"},
    )
    assert access_before.status_code == 403

    # 3. Owner views pending approvals
    pending_resp = client.get(
        "/access/requests/pending-approvals",
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert pending_resp.status_code == 200
    assert len(pending_resp.json()) == 1

    # 4. Owner approves request
    approve_resp = client.post(
        f"/access/requests/{request_id}/approve",
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert approve_resp.status_code == 200
    grant_data = approve_resp.json()
    assert grant_data["user_id"] == eng_user.id
    assert grant_data["resource_id"] == resource.id
    assert grant_data["permission"] == "read"

    # 5. After approval: Access to resource is ALLOWED via explicit grant
    access_after = client.get(
        f"/resources/{resource.id}",
        headers={"Authorization": f"Bearer {eng_token}"},
    )
    assert access_after.status_code == 200
    assert access_after.json()["id"] == resource.id


def test_non_owner_cannot_approve_request(client, db_session):
    hr_owner = db_session.query(User).filter_by(email="hr_owner@gnosis.com").first()
    eng_user = db_session.query(User).filter_by(email="eng_req@gnosis.com").first()
    resource = db_session.query(Resource).filter_by(name="HR Payroll Master").first()

    eng_token = create_access_token(subject=eng_user.id)

    # Requester submits request
    req_resp = client.post(
        "/access/requests",
        json={"resource_id": resource.id, "permission": "read", "reason": "Cross-dept audit"},
        headers={"Authorization": f"Bearer {eng_token}"},
    )
    request_id = req_resp.json()["id"]

    # Requester attempts to approve their own request -> DENIED (403)
    approve_resp = client.post(
        f"/access/requests/{request_id}/approve",
        headers={"Authorization": f"Bearer {eng_token}"},
    )
    assert approve_resp.status_code == 403


def test_owner_reject_request(client, db_session):
    hr_owner = db_session.query(User).filter_by(email="hr_owner@gnosis.com").first()
    eng_user = db_session.query(User).filter_by(email="eng_req@gnosis.com").first()
    resource = db_session.query(Resource).filter_by(name="HR Payroll Master").first()

    eng_token = create_access_token(subject=eng_user.id)
    owner_token = create_access_token(subject=hr_owner.id)

    # Submit request
    req_resp = client.post(
        "/access/requests",
        json={"resource_id": resource.id, "permission": "read", "reason": "Audit"},
        headers={"Authorization": f"Bearer {eng_token}"},
    )
    request_id = req_resp.json()["id"]

    # Owner rejects request
    reject_resp = client.post(
        f"/access/requests/{request_id}/reject",
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert reject_resp.status_code == 200
    assert reject_resp.json()["status"] == "REJECTED"

    # Access remains DENIED
    access = client.get(
        f"/resources/{resource.id}",
        headers={"Authorization": f"Bearer {eng_token}"},
    )
    assert access.status_code == 403


def test_cannot_reapprove_or_rereject_completed_request(client, db_session):
    hr_owner = db_session.query(User).filter_by(email="hr_owner@gnosis.com").first()
    eng_user = db_session.query(User).filter_by(email="eng_req@gnosis.com").first()
    resource = db_session.query(Resource).filter_by(name="HR Payroll Master").first()

    eng_token = create_access_token(subject=eng_user.id)
    owner_token = create_access_token(subject=hr_owner.id)

    # Submit and approve
    req_resp = client.post(
        "/access/requests",
        json={"resource_id": resource.id, "permission": "read", "reason": "Audit"},
        headers={"Authorization": f"Bearer {eng_token}"},
    )
    request_id = req_resp.json()["id"]

    client.post(
        f"/access/requests/{request_id}/approve",
        headers={"Authorization": f"Bearer {owner_token}"},
    )

    # Second approval attempt fails
    reapprove = client.post(
        f"/access/requests/{request_id}/approve",
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert reapprove.status_code == 400

    # Reject attempt on approved request fails
    rereject = client.post(
        f"/access/requests/{request_id}/reject",
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert rereject.status_code == 400