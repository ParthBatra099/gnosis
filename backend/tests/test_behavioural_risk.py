"""Stage 2 uses only the established in-memory, persisted-MFA fixture."""
from datetime import datetime, timedelta, timezone
import json
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (AuditEvent, BusinessRecord, DataDisclosure, Department, DepartmentAdminAssignment,
                        Incident, MonitoringScope, Resource, RiskAssessment, SecurityEvent, User)
from app.security import risk_scoring as policy
from app.security.detection_engine import evaluate_detection_rules, evaluate_disclosure_rules
from app.services.exposure_service import record_disclosures
from tests.test_exposure import data, login
from tests.test_mfa_workflows import world

AT = datetime(2026, 11, 8, 12, tzinfo=timezone.utc)


def audit(db, *, n, department="dept", outcome="DENY", at=AT, action="RESOURCE_ACCESS", resource_id="r"):
    row = AuditEvent(id=f"audit-{n}", actor_id="employee", resource_id=resource_id,
        action=action, outcome=outcome, reason="DENY_DEPARTMENT_MISMATCH", timestamp=at,
        context_data={"department_id": department, "response_id": f"response-{n}",
                      "session_ref": "f"*64, "representation": "business_records"})
    db.add(row); db.flush()
    return row


@pytest.mark.parametrize("metrics,level", [({}, "LOW"), ({"denials": 3, "business_attempts": 10}, "MEDIUM"),
    ({"distinct_records": 10, "business_attempts": 10, "denials": 3}, "HIGH"),
    ({"distinct_records": 10, "business_attempts": 10, "denials": 3, "sensitive": 5,
      "sensitive_responses": 3, "departments": 3, "max_severity": "CRITICAL"}, "CRITICAL")])
def test_pure_scores(metrics, level):
    result = policy.score_risk(metrics)
    assert result == policy.score_risk(metrics)
    assert result["level"] == level
    assert result["score"] == min(100, sum(f["contribution"] for f in result["factors"]))
    assert result["policy_version"] == "gnosis-observe-v1"


def test_denial_frequency_retry_and_no_exposure(data):
    with Session(data[0]) as db, db.begin():
        for n in range(10):
            row = audit(db, n=n)
            evaluate_detection_rules(db, row)
        before = db.query(SecurityEvent).count(), db.query(Incident).count(), db.query(RiskAssessment).count()
        evaluate_detection_rules(db, row)
        assert before == (db.query(SecurityEvent).count(), db.query(Incident).count(), db.query(RiskAssessment).count())
        kinds = {e.event_type for e in db.scalars(select(SecurityEvent))}
        assert {"REPEATED_DENIED_ACCESS", "REQUEST_FREQUENCY_ANOMALY"} <= kinds
        assert db.query(DataDisclosure).count() == 0
        assert {r.scope for r in db.scalars(select(RiskAssessment))} == {"REQUEST", "SESSION", "EMPLOYEE"}
        assert all(r.policy_version == policy.POLICY_VERSION for r in db.scalars(select(RiskAssessment)))
        assert all(r.evidence["metrics"]["disclosure_events"] == 0 for r in db.scalars(select(RiskAssessment)))


def test_sensitive_bulk_and_separate_responses(data):
    with Session(data[0]) as db, db.begin():
        resource = db.get(Resource, "r")
        resource.sensitivity = "CONFIDENTIAL"
        for n in range(12):
            db.add(BusinessRecord(id=f"s-{n}", resource_id="r", category="SYNTHETIC",
                sensitivity="CONFIDENTIAL", values={"fictional": "DO-NOT-COPY-SECRET-VALUE"}))
        db.flush()
        records = db.scalars(select(BusinessRecord).where(BusinessRecord.id.like("s-%"))).all()
        for n in range(3):
            record_disclosures(db, actor_id="employee", resource=resource, records=records,
                               response_id=f"disclose-{n}", session_id="fictional", timestamp=AT)
            evaluate_disclosure_rules(db, f"disclose-{n}")
        events = db.scalars(select(SecurityEvent)).all()
        assert {e.event_type for e in events} == {"BULK_DATA_DISCLOSURE", "REPEATED_SENSITIVE_DISCLOSURE"}
        assert db.query(DataDisclosure).count() == 36
        assert events[0].evidence["metrics"]["distinct_records"] == 12
        assert "DO-NOT-COPY-SECRET-VALUE" not in json.dumps([e.evidence for e in events])
        assert "DO-NOT-COPY-SECRET-VALUE" not in json.dumps([r.evidence for r in db.scalars(select(RiskAssessment))])


def test_actual_departments_not_resources_and_legitimate_hopping(data):
    with Session(data[0]) as db, db.begin():
        for n in range(3):
            row = audit(db, n=n, outcome="ALLOW")
            evaluate_detection_rules(db, row)
        assert not db.scalar(select(SecurityEvent).where(SecurityEvent.event_type == "DEPARTMENT_HOPPING"))
        db.add(Department(id="third", name="Third")); db.flush()
        row = audit(db, n=4, department="other", outcome="ALLOW")
        evaluate_detection_rules(db, row)
        row = audit(db, n=5, department="third", outcome="ALLOW")
        evaluate_detection_rules(db, row)
        event = db.scalar(select(SecurityEvent).where(SecurityEvent.event_type == "DEPARTMENT_HOPPING"))
        assert event.severity == "LOW" and event.evidence["count"] == 3
        assert set(db.scalars(select(MonitoringScope.department_id).where(MonitoringScope.security_event_id == event.id))) == {"dept", "other", "third"}


def test_irrelevant_actions_and_caller_transaction(data):
    with Session(data[0]) as db:
        with db.begin():
            db.get(Resource, "r").sensitivity = "CRITICAL"
            row = audit(db, n=0, action="ACCESS_REQUEST_CREATED")
            assert evaluate_detection_rules(db, row) == []
            assert db.query(SecurityEvent).count() == db.query(RiskAssessment).count() == 0
        with pytest.raises(RuntimeError), db.begin():
            for n in range(1, 4):
                row = audit(db, n=n)
                evaluate_detection_rules(db, row)
            raise RuntimeError("caller rollback")
        assert db.query(SecurityEvent).count() == db.query(RiskAssessment).count() == 0


def test_windows_and_legacy_incomplete_evidence(data):
    with Session(data[0]) as db, db.begin():
        audit(db, n=0, at=AT-timedelta(minutes=15, microseconds=1))
        audit(db, n=1, at=AT-timedelta(minutes=15))
        row = audit(db, n=2)
        evaluate_detection_rules(db, row)
        assert not db.scalar(select(SecurityEvent).where(SecurityEvent.event_type == "REPEATED_DENIED_ACCESS"))
        row = audit(db, n=3)
        row.context_data = {}
        db.flush()
        evaluate_detection_rules(db, row)
        assessment = db.scalars(select(RiskAssessment).where(RiskAssessment.scope == "EMPLOYEE")).all()[-1]
        assert assessment.evidence["coverage"] == "INCOMPLETE_OR_UNCONFIRMED"


def test_api_scope_and_no_identity_side_effects(data):
    with Session(data[0]) as db, db.begin():
        for n in range(3):
            evaluate_detection_rules(db, audit(db, n=n))
        before = [(u.id, u.organization_role, u.role, u.active) for u in db.scalars(select(User))]
    client = login(data, "admin")
    for path in ("/monitoring/detections", "/monitoring/risk-assessments", "/monitoring/risk/employees/employee", "/monitoring/risk/sessions/"+"f"*64):
        response = client.get(path)
        assert response.status_code == 200 and response.json()["total"] > 0
    with Session(data[0]) as db, db.begin():
        row = audit(db, n=4, department="other")
        evaluate_detection_rules(db, row)
    # A cross-scope assessment is hidden whole; it is never shown with a global score.
    admin_total = client.get("/monitoring/risk-assessments").json()["total"]
    global_total = login(data, "super").get("/monitoring/risk-assessments").json()["total"]
    assert admin_total < global_total
    client = login(data, "employee")
    assert client.get("/monitoring/risk-assessments").status_code == 403
    assert client.get("/monitoring/detections").status_code == 403
    with Session(data[0]) as db:
        assert before == [(u.id, u.organization_role, u.role, u.active) for u in db.scalars(select(User))]


def test_post_commit_disclosure_pipeline(data):
    client = login(data, "employee")
    assert client.get("/resources/r/records").status_code == 200
    with Session(data[0]) as db:
        assessments = db.scalars(select(RiskAssessment)).all()
        assert {r.scope for r in assessments} == {"REQUEST", "SESSION", "EMPLOYEE"}
        assert max(r.evidence["metrics"]["disclosure_events"] for r in assessments) == 3


def test_monitoring_failure_cannot_affect_disclosure(data, monkeypatch, caplog):
    import app.security.detection_engine as engine
    def fail(*args):
        raise ValueError("SECRET-DRIVER-PARAMETER")
    monkeypatch.setattr(engine, "evaluate_disclosure_rules", fail)
    client = login(data, "employee")
    assert client.get("/resources/r/records").status_code == 200
    assert "SECRET-DRIVER-PARAMETER" not in caplog.text
    assert "ledger retained" in caplog.text
    with Session(data[0]) as db:
        assert db.query(DataDisclosure).count() == 3


def test_critical_denial_not_suppressed_by_allowed_episode(data):
    with Session(data[0]) as db, db.begin():
        db.get(Resource, "r").sensitivity = "CRITICAL"
        evaluate_detection_rules(db, audit(db, n=0, outcome="ALLOW"))
        evaluate_detection_rules(db, audit(db, n=1, outcome="DENY"))
        events = db.scalars(select(SecurityEvent).where(SecurityEvent.event_type == "CRITICAL_RESOURCE_ACCESS")).all()
        assert {e.severity for e in events} == {"MEDIUM", "CRITICAL"}


def test_scope_revocation_and_evidence_across_all_consumers(data):
    with Session(data[0]) as db, db.begin():
        for n in range(3):
            evaluate_detection_rules(db, audit(db, n=n, department="other" if n == 2 else "dept"))
    client = login(data, "admin")
    # The trigger resource itself is visible, but combined evidence is not.
    assert client.get("/monitoring/detections").json()["total"] == 0
    assert client.get("/monitoring/security-events").json() == []
    assert client.get("/console/dashboard/summary").json()["total_open_incidents"] == 0
    with Session(data[0]) as db, db.begin():
        db.add(DepartmentAdminAssignment(user_id="admin", department_id="other", assigned_by="super"))
    assert client.get("/monitoring/detections").json()["total"] > 0
    with Session(data[0]) as db, db.begin():
        assignment = db.scalar(select(DepartmentAdminAssignment).where(DepartmentAdminAssignment.department_id == "other"))
        assignment.revoked_at = datetime.now(timezone.utc); assignment.revoked_by = "super"
    assert client.get("/monitoring/detections").json()["total"] == 0


def test_session_and_request_metrics_are_not_employee_totals(data):
    with Session(data[0]) as db, db.begin():
        for n in range(10):
            row = audit(db, n=n)
            if n < 9:
                row.context_data = {**row.context_data, "session_ref": "e"*64}
            db.flush()
        evaluate_detection_rules(db, row)
        employee = db.scalar(select(RiskAssessment).where(RiskAssessment.scope == "EMPLOYEE"))
        session = db.scalar(select(RiskAssessment).where(RiskAssessment.scope == "SESSION"))
        request = db.scalar(select(RiskAssessment).where(RiskAssessment.scope == "REQUEST"))
        assert employee.evidence["metrics"]["business_attempts"] == 10
        assert session.evidence["metrics"]["business_attempts"] == 1
        assert request.evidence["metrics"]["business_attempts"] == 1


@pytest.mark.parametrize("suffix", ["?limit=0", "?offset=-1", "?start=2026-01-01T00:00:00", "?scope=ADMIN"])
def test_monitoring_filter_validation(data, suffix):
    client = login(data, "super")
    assert client.get("/monitoring/risk-assessments"+suffix).status_code == 422


def test_risk_does_not_change_permissions_or_sessions(data):
    from app.models import AccessGrant, AuthenticationSession
    from app.security.access_decision import evaluate_access
    from app.services.authentication_transport import SESSION_COOKIE
    client = login(data, "employee")
    with Session(data[0]) as db:
        before = evaluate_access(db.get(User, "employee"), db.get(Resource, "hidden"), "read", [])
        sessions = [(s.id, s.revoked_at, s.security_generation) for s in db.scalars(select(AuthenticationSession))]
        assignments = [(a.id, a.revoked_at) for a in db.scalars(select(DepartmentAdminAssignment))]
        grants = db.query(AccessGrant).count()
    for _ in range(10):
        assert client.get("/resources/hidden/records").status_code == 403
    with Session(data[0]) as db:
        assert before == evaluate_access(db.get(User, "employee"), db.get(Resource, "hidden"), "read", [])
        assert sessions == [(s.id, s.revoked_at, s.security_generation) for s in db.scalars(select(AuthenticationSession))]
        assert assignments == [(a.id, a.revoked_at) for a in db.scalars(select(DepartmentAdminAssignment))]
        assert grants == db.query(AccessGrant).count()
        assert db.query(DataDisclosure).count() == 0


def test_cross_department_rule_evidence_respects_ten_minute_window(data):
    with Session(data[0]) as db, db.begin():
        audit(db, n=0, at=AT-timedelta(minutes=11))
        audit(db, n=1, resource_id="r")
        row = audit(db, n=2, resource_id="hidden", department="other")
        evaluate_detection_rules(db, row)
        event = db.scalar(select(SecurityEvent).where(SecurityEvent.event_type == "CROSS_DEPARTMENT_ANOMALY"))
        assert event.evidence["count"] == 2
        assert "audit-0" not in event.evidence["audit_ids"]
