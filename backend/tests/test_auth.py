from datetime import timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base, get_db
from app.core.security import create_access_token, hash_password
from app.main import app
from app.models.department import Department
from app.models.user import User


@pytest.fixture
def db_session():
    """Isolated SQLite in-memory DB configured for multi-threaded TestClient access."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()

    # Seed baseline department
    dept = Department(name="Security Engineering")
    session.add(dept)
    session.commit()

    # Seed active user
    active_user = User(
        name="Auth Test User",
        email="user@gnosis.com",
        password_hash=hash_password("CorrectPassword123!"),
        role="EMPLOYEE",
        department_id=dept.id,
        active=True,
    )
    # Seed inactive user
    inactive_user = User(
        name="Inactive User",
        email="inactive@gnosis.com",
        password_hash=hash_password("CorrectPassword123!"),
        role="EMPLOYEE",
        department_id=dept.id,
        active=False,
    )
    session.add_all([active_user, inactive_user])
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


def test_login_success(client):
    response = client.post(
        "/auth/login",
        json={"email": "user@gnosis.com", "password": "CorrectPassword123!"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_login_incorrect_password(client):
    response = client.post(
        "/auth/login",
        json={"email": "user@gnosis.com", "password": "WrongPassword!"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect email or password"


def test_login_nonexistent_email(client):
    response = client.post(
        "/auth/login",
        json={"email": "nobody@gnosis.com", "password": "CorrectPassword123!"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect email or password"


def test_login_inactive_user(client):
    response = client.post(
        "/auth/login",
        json={"email": "inactive@gnosis.com", "password": "CorrectPassword123!"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Inactive user account"


def test_authenticated_user_profile_success(client, db_session):
    user = db_session.query(User).filter_by(email="user@gnosis.com").first()
    token = create_access_token(subject=user.id)

    response = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    profile = response.json()
    assert profile["email"] == "user@gnosis.com"
    assert "password_hash" not in profile


def test_authenticated_user_invalid_token(client):
    response = client.get(
        "/auth/me",
        headers={"Authorization": "Bearer invalid_token_value"},
    )
    assert response.status_code == 401


def test_authenticated_user_expired_token(client, db_session):
    user = db_session.query(User).filter_by(email="user@gnosis.com").first()
    expired_token = create_access_token(
        subject=user.id,
        expires_delta=timedelta(seconds=-1),
    )

    response = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Token has expired"