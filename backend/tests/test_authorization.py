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
from app.security.access_decision import DecisionReason, DecisionStatus, evaluate_access


@pytest.fixture
def db_session():
    """Isolated SQLite in-memory DB for authorization tests."""
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
        name="HR Worker",
        email="hr@gnosis.com",
        password_hash=hash_password("Pass123!"),
        role="EMPLOYEE",
        department_id=hr_dept.id,
        active=True,
    )
    eng_user = User(
        name="Eng Worker",
        email="eng@gnosis.com",
        password_hash=hash_password("Pass123!"),
        role="EMPLOYEE",
        department_id=eng_dept.id,
        active=True,
    )
    inactive_user = User(
        name="Inactive Worker",
        email="inactive_user@gnosis.com",
        password_hash=hash_password("Pass123!"),
        role="EMPLOYEE",
        department_id=hr_dept.id,
        active=False,
    )
    session.add_all([hr_user, eng_user, inactive_user])
    session.commit()

    # Seed resources
    hr_res = Resource(
        name="HR Payroll Data",
        description="Payroll details",
        department_id=hr_dept.id,
        owner_id=hr_user.id,
        sensitivity="INTERNAL",
    )
    eng_res = Resource(
        name="Engineering Docs",
        description="System Architecture Specs",
        department_id=eng_dept.id,
        owner_id=eng_user.id,
        sensitivity="INTERNAL",
    )
    critical_res = Resource(
        name="Encryption Keys",
        description="Root master keys",
        department_id=hr_dept.id,
        owner_id=hr_user.id,
        sensitivity="CRITICAL",
    )
    session.add_all([hr_res, eng_res, critical_res])
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


def test_unit_evaluate_access_same_department(db_session):
    user = db_session.query(User).filter_by(email="hr@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Payroll Data").first()

    decision = evaluate_access(user, res, "read")
    assert decision.status == DecisionStatus.ALLOW
    assert decision.reason == DecisionReason.ALLOW_RESOURCE_OWNER
    assert decision.allowed is True


def test_unit_evaluate_access_department_mismatch(db_session):
    user = db_session.query(User).filter_by(email="eng@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Payroll Data").first()

    decision = evaluate_access(user, res, "read")
    assert decision.status == DecisionStatus.DENY
    assert decision.reason == DecisionReason.DENY_DEPARTMENT_MISMATCH
    assert decision.allowed is False


def test_unit_evaluate_access_unsupported_permission(db_session):
    user = db_session.query(User).filter_by(email="hr@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Payroll Data").first()

    decision = evaluate_access(user, res, "execute_code")
    assert decision.status == DecisionStatus.DENY
    assert decision.reason == DecisionReason.DENY_UNSUPPORTED_PERMISSION
    assert decision.allowed is False


def test_endpoint_allow_same_department_access(client, db_session):
    user = db_session.query(User).filter_by(email="hr@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Payroll Data").first()
    token = create_access_token(subject=user.id)

    response = client.get(
        f"/resources/{res.id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == res.id
    assert data["name"] == "HR Payroll Data"


def test_endpoint_deny_cross_department_access(client, db_session):
    user = db_session.query(User).filter_by(email="eng@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Payroll Data").first()
    token = create_access_token(subject=user.id)

    response = client.get(
        f"/resources/{res.id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403
    err = response.json()["detail"]
    assert err["reason"] == DecisionReason.DENY_DEPARTMENT_MISMATCH.value


def test_endpoint_unauthenticated_access(client, db_session):
    res = db_session.query(Resource).filter_by(name="HR Payroll Data").first()
    response = client.get(f"/resources/{res.id}")
    assert response.status_code == 401


def test_endpoint_nonexistent_resource(client, db_session):
    user = db_session.query(User).filter_by(email="hr@gnosis.com").first()
    token = create_access_token(subject=user.id)

    response = client.get(
        "/resources/nonexistent-id-9999",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404


def test_endpoint_unsupported_permission(client, db_session):
    user = db_session.query(User).filter_by(email="hr@gnosis.com").first()
    res = db_session.query(Resource).filter_by(name="HR Payroll Data").first()
    token = create_access_token(subject=user.id)

    response = client.get(
        f"/resources/{res.id}?permission=admin_override",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403
    err = response.json()["detail"]
    assert err["reason"] == DecisionReason.DENY_UNSUPPORTED_PERMISSION.value