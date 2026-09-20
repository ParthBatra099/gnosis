import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

from app.core.database import Base
from app.models.department import Department
from app.models.user import User
from app.models.resource import Resource
from app.models.permission import Permission


@pytest.fixture
def db_session():
    """In-memory SQLite session fixture for isolated model testing."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


def test_department_persistence(db_session):
    dept = Department(name="Engineering", description="Core engineering team")
    db_session.add(dept)
    db_session.commit()

    saved = db_session.query(Department).filter_by(name="Engineering").first()
    assert saved is not None
    assert saved.id is not None
    assert saved.description == "Core engineering team"


def test_user_persistence_and_department_relationship(db_session):
    dept = Department(name="Security")
    db_session.add(dept)
    db_session.commit()

    user = User(
        name="Alice Smith",
        email="alice@gnosis.local",
        password_hash="secret_hash",
        role="SECURITY_ANALYST",
        department_id=dept.id,
    )
    db_session.add(user)
    db_session.commit()

    saved_user = db_session.query(User).filter_by(email="alice@gnosis.local").first()
    assert saved_user is not None
    assert saved_user.department.name == "Security"


def test_resource_persistence_and_relationships(db_session):
    dept = Department(name="HR")
    db_session.add(dept)
    db_session.commit()

    owner = User(
        name="Bob Owner",
        email="bob@gnosis.local",
        password_hash="secret_hash",
        role="RESOURCE_OWNER",
        department_id=dept.id,
    )
    db_session.add(owner)
    db_session.commit()

    res = Resource(
        name="2026 Payroll Data",
        description="Confidential HR compensation details",
        department_id=dept.id,
        owner_id=owner.id,
        sensitivity="CRITICAL",
    )
    db_session.add(res)
    db_session.commit()

    saved_res = db_session.query(Resource).filter_by(name="2026 Payroll Data").first()
    assert saved_res is not None
    assert saved_res.department.name == "HR"
    assert saved_res.owner.email == "bob@gnosis.local"
    assert saved_res.sensitivity == "CRITICAL"


def test_permission_persistence(db_session):
    perm = Permission(name="resources:read", description="Allows reading resource metadata")
    db_session.add(perm)
    db_session.commit()

    saved_perm = db_session.query(Permission).filter_by(name="resources:read").first()
    assert saved_perm is not None
    assert saved_perm.description == "Allows reading resource metadata"


def test_department_name_uniqueness(db_session):
    dept1 = Department(name="Finance")
    dept2 = Department(name="Finance")
    db_session.add(dept1)
    db_session.commit()

    db_session.add(dept2)
    with pytest.raises(IntegrityError):
        db_session.commit()


def test_user_email_uniqueness(db_session):
    dept = Department(name="Sales")
    db_session.add(dept)
    db_session.commit()

    u1 = User(name="User1", email="same@gnosis.local", password_hash="h1", department_id=dept.id)
    u2 = User(name="User2", email="same@gnosis.local", password_hash="h2", department_id=dept.id)
    db_session.add(u1)
    db_session.commit()

    db_session.add(u2)
    with pytest.raises(IntegrityError):
        db_session.commit()