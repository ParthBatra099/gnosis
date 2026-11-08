import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.core.database import Base
from app.models.department import Department
from app.models.resource import Resource
from app.models.user import User
from app.models.access_request import AccessRequest
from app.models.access_grant import AccessGrant
from app.services.assistant_service import AssistantService
from app.core.security import hash_password


@pytest.mark.parametrize("state,active", [
    ("non_expiring", True), ("future", True), ("expired", False),
    ("revoked", False), ("exact_expiry", False),
])
def test_assistant_reports_only_active_grants(setup_assistant_data, state, active):
    data = setup_assistant_data
    session, user = data["session"], data["user"]
    grant = session.query(AccessGrant).filter_by(user_id=user.id).one()
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    if state == "future":
        grant.expires_at = now + timedelta(days=1)
    elif state == "expired":
        grant.expires_at = now - timedelta(seconds=1)
    elif state == "exact_expiry":
        grant.expires_at = now
    elif state == "revoked":
        grant.revoked_at = now
    session.commit()
    grant_id = grant.id
    with patch("app.services.assistant_service.datetime", wraps=datetime, create=True) as clock:
        clock.now.return_value = now
        result = AssistantService.process_query(session, user, "Show my active access grants")
    assert (f"AccessGrant:{grant_id}" in result.sources) is active
    assert (data["public_res_name"] in result.answer) is active
    assert session.get(AccessGrant, grant_id) is not None


@pytest.fixture
def setup_assistant_data():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    unique_suffix = str(uuid.uuid4())[:8]

    try:
        # 1. Create Isolated Test Departments with Unique Names
        it_dept = Department(
            name=f"IT_ASSIST_TEST_{unique_suffix}",
            description="IT Test Dept",
        )
        hr_dept = Department(
            name=f"HR_ASSIST_TEST_{unique_suffix}",
            description="HR Test Dept",
        )
        session.add_all([it_dept, hr_dept])
        session.commit()

        # 2. Create Isolated Test Users with Unique Emails.
        #    The restricted resource needs a DIFFERENT owner, otherwise
        #    evaluate_access allows the employee through the resource-owner rule.
        emp = User(
            name="Assistant Employee Test",
            email=f"assist.emp.{unique_suffix}@gnosis.com",
            password_hash=hash_password("Pass@123"),
            role="EMPLOYEE",
            organization_role="EMPLOYEE",
            department_id=hr_dept.id,
            active=True,
        )
        owner = User(
            name="Assistant Owner Test",
            email=f"assist.owner.{unique_suffix}@gnosis.com",
            password_hash=hash_password("Pass@123"),
            role="EMPLOYEE",
            organization_role="EMPLOYEE",
            department_id=it_dept.id,
            active=True,
        )
        session.add_all([emp, owner])
        session.commit()

        # 3. Create Isolated Test Resources using 'sensitivity' field
        public_res_name = f"Public Employee Guide {unique_suffix}"
        restricted_res_name = f"Restricted Core Vault {unique_suffix}"

        public_res = Resource(
            name=public_res_name,
            description="Public handbook",
            sensitivity="PUBLIC",
            department_id=hr_dept.id,
            owner_id=emp.id,
        )
        restricted_res = Resource(
            name=restricted_res_name,
            description="High security secrets",
            sensitivity="RESTRICTED",
            department_id=it_dept.id,
            owner_id=owner.id,
        )
        session.add_all([public_res, restricted_res])
        session.commit()

        # 4. Create Isolated Access Request using 'requester_id' and 'permission'
        acc_req = AccessRequest(
            requester_id=emp.id,
            resource_id=restricted_res.id,
            permission="READ",
            reason="Need clearance",
            status="PENDING",
        )

        # Isolated Access Grant. access_grants.permission is NOT NULL with no default,
        # and evaluate_access compares it exactly to lowercase "read".
        acc_grant = AccessGrant(
            user_id=emp.id,
            resource_id=public_res.id,
            granted_by=emp.id,
            permission="read",
        )
        session.add_all([acc_req, acc_grant])
        session.commit()

        yield {
            "session": session,
            "user": emp,
            "owner": owner,
            "public_res": public_res,
            "restricted_res": restricted_res,
            "public_res_name": public_res_name,
            "restricted_res_name": restricted_res_name,
        }

    finally:
        session.close()
        engine.dispose()


def test_assistant_authorized_resource_query(setup_assistant_data):
    session = setup_assistant_data["session"]
    user = setup_assistant_data["user"]
    res_name = setup_assistant_data["public_res_name"]

    res = AssistantService.process_query(
        session, user, f"Tell me about {res_name}"
    )
    assert res.access_denied is False
    assert res_name in res.answer
    assert "PUBLIC" in res.answer


def test_assistant_unauthorized_resource_query(setup_assistant_data):
    session = setup_assistant_data["session"]
    user = setup_assistant_data["user"]
    res_name = setup_assistant_data["restricted_res_name"]

    res = AssistantService.process_query(
        session, user, f"Show me {res_name}"
    )
    # Unauthorized must be indistinguishable from nonexistent: no name, no metadata.
    assert res.answer == "No relevant information was found."
    assert res.sources == []
    assert res_name not in res.answer
    assert "RESTRICTED" not in res.answer


def test_assistant_nonexistent_resource_query(setup_assistant_data):
    session = setup_assistant_data["session"]
    user = setup_assistant_data["user"]
    res = AssistantService.process_query(
        session, user, "Tell me about Nonexistent Super File"
    )
    assert res.access_denied is False
    assert res.answer == "No relevant information was found."


def test_assistant_unauthorized_and_missing_are_indistinguishable(setup_assistant_data):
    session = setup_assistant_data["session"]
    user = setup_assistant_data["user"]
    res_name = setup_assistant_data["restricted_res_name"]

    denied = AssistantService.process_query(session, user, f"Show me {res_name}")
    missing = AssistantService.process_query(
        session, user, "Show me Nonexistent Super File"
    )
    assert denied == missing


def test_assistant_unsupported_query(setup_assistant_data):
    session = setup_assistant_data["session"]
    user = setup_assistant_data["user"]
    res = AssistantService.process_query(
        session, user, "What is the capital of France?"
    )
    assert res.access_denied is False
    assert "not currently supported" in res.answer


def test_assistant_own_access_requests_query(setup_assistant_data):
    session = setup_assistant_data["session"]
    user = setup_assistant_data["user"]
    res_name = setup_assistant_data["restricted_res_name"]

    res = AssistantService.process_query(session, user, "What are my pending requests?")
    assert res.access_denied is False
    assert res_name in res.answer
    assert "PENDING" in res.answer


def test_assistant_own_access_grants_query(setup_assistant_data):
    session = setup_assistant_data["session"]
    user = setup_assistant_data["user"]
    res_name = setup_assistant_data["public_res_name"]

    res = AssistantService.process_query(session, user, "Show my active access grants")
    assert res.access_denied is False
    assert res_name in res.answer


def test_assistant_own_profile_query(setup_assistant_data):
    session = setup_assistant_data["session"]
    user = setup_assistant_data["user"]

    res = AssistantService.process_query(session, user, "Show my profile info")
    assert res.access_denied is False
    assert user.name in res.answer
    assert user.email in res.answer
