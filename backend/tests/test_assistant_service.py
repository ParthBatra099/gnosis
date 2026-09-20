import uuid
import pytest
from app.core.database import SessionLocal
from app.models.department import Department
from app.models.resource import Resource
from app.models.user import User
from app.models.access_request import AccessRequest
from app.models.access_grant import AccessGrant
from app.services.assistant_service import AssistantService
from app.core.security import hash_password


@pytest.fixture
def setup_assistant_data():
    session = SessionLocal()
    unique_suffix = str(uuid.uuid4())[:8]

    created_ids = {
        "grants": [],
        "requests": [],
        "resources": [],
        "users": [],
        "departments": [],
    }

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
        created_ids["departments"].extend([it_dept.id, hr_dept.id])

        # 2. Create Isolated Test Users with Unique Emails.
        #    The restricted resource needs a DIFFERENT owner, otherwise
        #    evaluate_access allows the employee through the resource-owner rule.
        emp = User(
            name="Assistant Employee Test",
            email=f"assist.emp.{unique_suffix}@gnosis.com",
            password_hash=hash_password("Pass@123"),
            role="EMPLOYEE",
            department_id=hr_dept.id,
            active=True,
        )
        owner = User(
            name="Assistant Owner Test",
            email=f"assist.owner.{unique_suffix}@gnosis.com",
            password_hash=hash_password("Pass@123"),
            role="EMPLOYEE",
            department_id=it_dept.id,
            active=True,
        )
        session.add_all([emp, owner])
        session.commit()
        created_ids["users"].extend([emp.id, owner.id])

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
        created_ids["resources"].extend([public_res.id, restricted_res.id])

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
        created_ids["requests"].append(acc_req.id)
        created_ids["grants"].append(acc_grant.id)

        yield {
            "session": session,
            "user": emp,
            "owner": owner,
            "public_res": public_res,
            "restricted_res": restricted_res,
            "public_res_name": public_res_name,
            "restricted_res_name": restricted_res_name,
        }

    except Exception:
        session.rollback()
        # Clean up any IDs recorded up to the point of failure
        if created_ids["grants"]:
            session.query(AccessGrant).filter(
                AccessGrant.id.in_(created_ids["grants"])
            ).delete(synchronize_session=False)
        if created_ids["requests"]:
            session.query(AccessRequest).filter(
                AccessRequest.id.in_(created_ids["requests"])
            ).delete(synchronize_session=False)
        if created_ids["resources"]:
            session.query(Resource).filter(
                Resource.id.in_(created_ids["resources"])
            ).delete(synchronize_session=False)
        if created_ids["users"]:
            session.query(User).filter(
                User.id.in_(created_ids["users"])
            ).delete(synchronize_session=False)
        if created_ids["departments"]:
            session.query(Department).filter(
                Department.id.in_(created_ids["departments"])
            ).delete(synchronize_session=False)
        session.commit()
        session.close()
        raise

    finally:
        # Normal cleanup order: AccessGrant -> AccessRequest -> Resource -> User -> Department
        if created_ids["grants"]:
            session.query(AccessGrant).filter(
                AccessGrant.id.in_(created_ids["grants"])
            ).delete(synchronize_session=False)
        if created_ids["requests"]:
            session.query(AccessRequest).filter(
                AccessRequest.id.in_(created_ids["requests"])
            ).delete(synchronize_session=False)
        if created_ids["resources"]:
            session.query(Resource).filter(
                Resource.id.in_(created_ids["resources"])
            ).delete(synchronize_session=False)
        if created_ids["users"]:
            session.query(User).filter(
                User.id.in_(created_ids["users"])
            ).delete(synchronize_session=False)
        if created_ids["departments"]:
            session.query(Department).filter(
                Department.id.in_(created_ids["departments"])
            ).delete(synchronize_session=False)

        session.commit()
        session.close()


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