"""Stage 1 integration on the existing persisted-MFA, memory-only fixture."""
from datetime import datetime, timedelta, timezone
import hashlib

import pytest
from sqlalchemy import event, select
from sqlalchemy.orm import Session

from app.models import BusinessRecord, DataDisclosure, Department, DepartmentAdminAssignment, Resource, User
from app.services.exposure_service import record_disclosures, synthetic_records, summarize, filtered_disclosures
from app.services.authentication_transport import SESSION_COOKIE
from tests.authentication_support import session_token
from tests.test_mfa_workflows import world


@pytest.fixture
def data(world):
    engine, client, _ = world
    with Session(engine) as db, db.begin():
        db.add(Department(id="other", name="Other")); db.flush()
        db.add_all([Resource(id="r", name="Synthetic budgets", department_id="dept", owner_id="employee", sensitivity="INTERNAL"),
                    Resource(id="hidden", name="Hidden", department_id="other", owner_id="super", sensitivity="INTERNAL"),
                    Resource(id="empty", name="Empty", department_id="dept", owner_id="employee", sensitivity="INTERNAL")])
        db.flush()
        db.add_all(synthetic_records("r") + synthetic_records("hidden"))
        db.add(DepartmentAdminAssignment(user_id="admin", department_id="dept", assigned_by="super"))
    return world


def login(data, actor):
    engine, client, _ = data
    with Session(engine) as db:
        token = session_token(db, actor)
    client.cookies.set(SESSION_COOKIE, token)
    return client


def test_success_repeat_empty_and_metadata(data):
    client = login(data, "employee")
    for path in ("/resources/r", "/access/resources/metadata"):
        assert client.get(path).status_code == 200
    from tests.test_mfa_workflows import post
    assert post(client, "/assistant/query", {"query": "Tell me about Synthetic budgets"}).status_code == 200
    with Session(data[0]) as db:
        assert db.query(DataDisclosure).count() == 0
    first = client.get("/resources/r/records?limit=2")
    second = client.get("/resources/r/records?limit=2")
    assert first.status_code == second.status_code == 200
    assert len(first.json()["records"]) == 2
    assert first.json()["response_id"] != second.json()["response_id"]
    assert client.get("/resources/empty/records").json()["records"] == []
    with Session(data[0]) as db:
        assert db.query(DataDisclosure).count() == 4
        rows = db.scalars(select(DataDisclosure)).all()
        assert all(r.completion_state == "APPLICATION_COMPLETE" and r.transport_state == "UNKNOWN" for r in rows)
        assert all(r.session_ref and len(r.session_ref) == 64 for r in rows)
        assert not hasattr(rows[0], "values")
    client = login(data, "super")
    summary = client.get("/monitoring/exposure/summary").json()
    assert (summary["disclosure_events"], summary["distinct_records"], summary["repeated_disclosures"]) == (4, 2, 2)
    assert summary["by_department"][0]["key"] == "dept"
    assert summary["by_category"][0]["key"] == "SYNTHETIC_BUDGET"


def test_denial_failure_and_no_session(data):
    client = data[1]
    assert client.get("/resources/r/records").status_code == 401
    client = login(data, "employee")
    assert client.get("/resources/hidden/records").status_code == 403
    assert client.get("/resources/missing/records").status_code == 404
    def fail(*args):
        raise RuntimeError("fictional capture failure")
    event.listen(DataDisclosure, "before_insert", fail)
    try:
        assert client.get("/resources/r/records").status_code == 503
    finally:
        event.remove(DataDisclosure, "before_insert", fail)
    with Session(data[0]) as db:
        assert db.query(DataDisclosure).count() == 0


def test_idempotency_windows_and_groups(data):
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with Session(data[0]) as db, db.begin():
        resource = db.get(Resource, "r")
        records = db.scalars(select(BusinessRecord).where(BusinessRecord.resource_id == "r")).all()
        kwargs = dict(actor_id="employee", resource=resource, records=records + records,
                      response_id="response-one", session_id="fictional-session", timestamp=start)
        record_disclosures(db, **kwargs)
        record_disclosures(db, **kwargs)
        assert db.query(DataDisclosure).count() == 3
        record_disclosures(db, **{**kwargs, "response_id": "response-two", "timestamp": start + timedelta(hours=1)})
        query = filtered_disclosures(db, "super", start=start, end=start+timedelta(hours=1))
        result = summarize(db, query)
        assert result["disclosure_events"] == result["distinct_records"] == 3
        assert result["by_employee"] == [{"key": "employee", "disclosure_events": 3, "distinct_records": 3}]
        assert result["by_session"][0]["key"] == hashlib.sha256(b"fictional-session").hexdigest()
        assert summarize(db, filtered_disclosures(db, "super"))["repeated_disclosures"] == 3
        assert summarize(db, filtered_disclosures(db, "super", start=start+timedelta(days=1)))["disclosure_events"] == 0
        with pytest.raises(ValueError, match="Conflicting"):
            record_disclosures(db, **{**kwargs, "actor_id": "super"})


@pytest.mark.parametrize("actor,status", [("super", 200), ("admin", 200), ("employee", 403)])
def test_scope_and_pagination(data, actor, status):
    login(data, "employee").get("/resources/r/records")
    login(data, "super").get("/resources/hidden/records")
    client = login(data, actor)
    for path in ("/monitoring/exposure/summary", "/monitoring/exposure/events?limit=1", "/monitoring/exposure/employees/employee"):
        response = client.get(path)
        assert response.status_code == status
    if status == 200:
        page = client.get("/monitoring/exposure/events?limit=1").json()
        assert page["total"] == (6 if actor == "super" else 3)
        assert len(page["items"]) == 1
        hidden = client.get("/monitoring/exposure/employees/super").json()
        assert hidden["disclosure_events"] == (3 if actor == "super" else 0)


def test_history_and_assignment_revocation(data):
    login(data, "employee").get("/resources/r/records")
    with Session(data[0]) as db, db.begin():
        db.get(Resource, "r").department_id = "other"
        db.get(User, "employee").department_id = "other"
    client = login(data, "admin")
    assert client.get("/monitoring/exposure/summary").json()["disclosure_events"] == 3
    with Session(data[0]) as db, db.begin():
        assignment = db.scalar(select(DepartmentAdminAssignment))
        assignment.revoked_at = datetime.now(timezone.utc)
        assignment.revoked_by = "super"
    assert client.get("/monitoring/exposure/summary").status_code == 403


@pytest.mark.parametrize("query", ["limit=0", "start=2026-01-01T00:00:00", "start=2026-02-01T00:00:00Z&end=2026-01-01T00:00:00Z"])
def test_invalid_filters(data, query):
    client = login(data, "super")
    path = "/monitoring/exposure/events?" + query
    assert client.get(path).status_code == 422


def test_serialization_failure_cannot_create_evidence(data, monkeypatch):
    from app.schemas.exposure import BusinessRecordsResponse
    def fail(*args, **kwargs):
        raise ValueError("fictional serialization failure")
    monkeypatch.setattr(BusinessRecordsResponse, "model_dump_json", fail)
    client = login(data, "employee")
    assert client.get("/resources/r/records").status_code == 503
    with Session(data[0]) as db:
        assert db.query(DataDisclosure).count() == 0


def test_mid_batch_failure_rolls_back_every_record(data):
    client = login(data, "employee")
    attempts = []
    def fail_second(mapper, connection, target):
        attempts.append(target.record_id)
        if len(attempts) == 2:
            raise RuntimeError("fictional partial insert failure")
    event.listen(DataDisclosure, "before_insert", fail_second)
    try:
        assert client.get("/resources/r/records").status_code == 503
    finally:
        event.remove(DataDisclosure, "before_insert", fail_second)
    assert len(attempts) == 2
    with Session(data[0]) as db:
        assert db.query(DataDisclosure).count() == 0


def test_existing_best_effort_audit_policy_unchanged(data):
    from app.models import AuditEvent
    client = login(data, "employee")
    def fail_resource_audit(mapper, connection, target):
        if target.action == "RESOURCE_ACCESS":
            raise RuntimeError("fictional best effort audit failure")
    event.listen(AuditEvent, "before_insert", fail_resource_audit)
    try:
        assert client.get("/resources/r/records").status_code == 200
    finally:
        event.remove(AuditEvent, "before_insert", fail_resource_audit)
    with Session(data[0]) as db:
        assert db.query(DataDisclosure).count() == 3


def test_grants_and_pending_requests_are_not_exposure(data):
    from tests.test_mfa_workflows import post
    client = login(data, "employee")
    response = post(client, "/access/requests", {"resource_id": "hidden", "permission": "read", "reason": "Fictional test"})
    assert response.status_code == 201
    request_id = response.json()["id"]
    client = login(data, "super")
    assert post(client, f"/access/requests/{request_id}/approve", {}).status_code == 200
    with Session(data[0]) as db:
        assert db.query(DataDisclosure).count() == 0


def test_multiple_departments_categories_and_session_filter(data):
    with Session(data[0]) as db, db.begin():
        db.add(DepartmentAdminAssignment(user_id="admin", department_id="other", assigned_by="super"))
        db.get(BusinessRecord, "hidden:demo:1").category = "SYNTHETIC_SALES"
    login(data, "employee").get("/resources/r/records")
    login(data, "super").get("/resources/hidden/records")
    client = login(data, "admin")
    result = client.get("/monitoring/exposure/summary").json()
    assert result["disclosure_events"] == 6
    assert {r["key"]: r["disclosure_events"] for r in result["by_department"]} == {"dept": 3, "other": 3}
    assert {r["key"]: r["disclosure_events"] for r in result["by_category"]} == {"SYNTHETIC_BUDGET": 5, "SYNTHETIC_SALES": 1}
    ref = result["by_session"][0]["key"]
    assert client.get("/monitoring/exposure/summary", params={"session_ref": ref}).json()["disclosure_events"] == 3
    first = client.get("/monitoring/exposure/events?limit=1&offset=0").json()["items"][0]
    second = client.get("/monitoring/exposure/events?limit=1&offset=1").json()["items"][0]
    assert first["id"] != second["id"]
    assert "values" not in first


def test_record_classification_mismatch_and_bounded_repository(data):
    from app.services.exposure_service import retrieve_records
    with Session(data[0]) as db, db.begin():
        db.get(BusinessRecord, "r:demo:1").sensitivity = "CRITICAL"
    client = login(data, "employee")
    assert client.get("/resources/r/records").status_code == 503
    with Session(data[0]) as db:
        assert db.query(DataDisclosure).count() == 0
        with pytest.raises(ValueError):
            retrieve_records(db, db.get(Resource, "r"), limit=101)
