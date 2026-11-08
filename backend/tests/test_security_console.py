from datetime import datetime, timedelta, timezone
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditEvent, Incident, IncidentEvent, SecurityEvent, DepartmentAdminAssignment, RiskAssessment
from app.security.detection_engine import evaluate_detection_rules
from tests.test_behavioural_risk import audit, AT
from tests.test_exposure import data, login
from tests.test_mfa_workflows import world


def test_timeline_sources_privacy_filters_and_pagination(data):
    client = login(data, "employee")
    assert client.get("/resources/r/records").status_code == 200
    assert client.get("/resources/hidden/records").status_code == 403
    client = login(data, "super")
    result = client.get("/monitoring/timeline?limit=100").json()
    assert result["total"] == len(result["items"])
    assert {"ACCESS_ALLOWED", "ACCESS_DENIED", "DATA_DISCLOSED", "RISK_ASSESSMENT"} <= {r["category"] for r in result["items"]}
    disclosed = [r for r in result["items"] if r["category"] == "DATA_DISCLOSED"]
    assert len(disclosed) == 3
    assert all(r["transport_state"] == "UNKNOWN" and r["outcome"] == "APPLICATION_COMPLETE" for r in disclosed)
    assert all(r["resource_id"] == "r" for r in disclosed)
    assert "Fictional Project" not in str(result)
    dates = [datetime.fromisoformat(r["timestamp"].replace("Z", "+00:00")) for r in result["items"]]
    assert dates == sorted(dates, reverse=True)
    page1 = client.get("/monitoring/timeline?limit=1&offset=0").json()
    page2 = client.get("/monitoring/timeline?limit=1&offset=1").json()
    assert page1["total"] == page2["total"] == result["total"]
    assert page1["items"][0]["id"] != page2["items"][0]["id"]
    filtered = client.get("/monitoring/timeline?category=DATA_DISCLOSED&employee_id=employee").json()
    assert filtered["total"] == 3
    assert client.get("/monitoring/timeline?employee_id=missing").json()["total"] == 0


def test_overview_persisted_metrics_and_latest_risk(data):
    login(data, "employee").get("/resources/r/records")
    client = login(data, "super")
    result = client.get("/console/dashboard/security-overview").json()
    assert result["disclosure_events"] == 3 and result["distinct_records"] == 3
    assert result["elevated_employees"] == 0
    assert result["employee_risks"] and result["recent_activity"]
    assert result["open_incidents"] == 0
    assert client.get("/console/incidents/page").json()["total"] == 0


def test_cross_department_incident_cannot_leak_through_audits_or_links(data):
    with Session(data[0]) as db, db.begin():
        visible = SecurityEvent(id="visible", actor_id="employee", resource_id="r", event_type="TEST", severity="HIGH", description="Visible")
        hidden = SecurityEvent(id="hidden-event", actor_id="super", resource_id="hidden", event_type="TEST", severity="HIGH", description="SECRET-HIDDEN-EVIDENCE")
        db.add_all([visible, hidden]); db.flush()
        db.add(Incident(id="mixed", title="SECRET-INCIDENT", description="Hidden", severity="HIGH", status="OPEN", resource_id="r", reporter_id="employee")); db.flush()
        db.add_all([IncidentEvent(incident_id="mixed", security_event_id="visible"), IncidentEvent(incident_id="mixed", security_event_id="hidden-event")])
        db.add(AuditEvent(actor_id="admin", resource_id="r", action="INCIDENT_UPDATED", outcome="ALLOW",
                          context_data={"incident_id": "mixed", "status": "INVESTIGATING", "secret": "RAW-SESSION-SECRET"}))
    client = login(data, "admin")
    assert client.get("/console/incidents/page").json()["total"] == 0
    assert client.get("/console/incidents/mixed").status_code == 404
    events = client.get("/monitoring/detections").json()
    assert events["total"] == 1 and events["items"][0]["related_incidents"] == []
    assert client.get("/monitoring/detections?incident_status=OPEN").json()["total"] == 0
    timeline = client.get("/monitoring/timeline?limit=100").json()
    assert "mixed" not in str(timeline) and "SECRET" not in str(timeline)
    assert "mixed" not in str(client.get("/monitoring/audit-logs").json())
    assert client.get("/console/dashboard/security-overview").json()["open_incidents"] == 0
    with Session(data[0]) as db, db.begin():
        db.add(DepartmentAdminAssignment(user_id="admin", department_id="other", assigned_by="super"))
    assert client.get("/console/incidents/page").json()["total"] == 1
    assert client.get("/monitoring/detections?incident_status=OPEN").json()["total"] == 2


def test_incident_lifecycle_detail_history_and_timeline(data):
    from tests.test_mfa_workflows import post
    client = login(data, "super")
    created = post(client, "/console/incidents", {"title": "Review fixture", "description": "Synthetic review", "severity": "HIGH", "resource_id": "r"})
    assert created.status_code == 201
    identifier = created.json()["id"]
    from app.services.authentication_transport import CSRF_COOKIE
    def patch(payload):
        csrf = client.get("/auth/csrf", headers={"Origin": "https://testserver"}).json()["csrf_token"]
        return client.patch("/console/incidents/"+identifier, json=payload, headers={"Origin": "https://testserver", "X-CSRF-Token": csrf})
    assert patch({"status": "CLOSED"}).status_code == 400
    assert patch({"status": "INVESTIGATING"}).status_code == 200
    assert patch({"status": "RESOLVED"}).status_code == 400
    assert patch({"status": "RESOLVED", "resolution_notes": "Reviewed synthetic evidence"}).status_code == 200
    assert patch({"status": "CLOSED"}).status_code == 200
    detail = client.get("/console/incidents/"+identifier).json()
    assert detail["status"] == "CLOSED" and len(detail["history"]) == 4
    assert detail["resolution_notes"] == "Reviewed synthetic evidence"
    timeline = client.get("/monitoring/timeline?category=INCIDENT_UPDATED").json()
    assert timeline["total"] == 3


@pytest.mark.parametrize("path", ["/monitoring/timeline", "/console/dashboard/security-overview", "/console/incidents/page"])
def test_employee_denied(data, path):
    assert login(data, "employee").get(path).status_code == 403


@pytest.mark.parametrize("suffix", ["limit=0", "offset=-1", "category=UNKNOWN", "start=2026-01-01T00:00:00", "start=2026-02-01T00:00:00Z&end=2026-01-01T00:00:00Z"])
def test_timeline_invalid_filters(data, suffix):
    assert login(data, "super").get("/monitoring/timeline?"+suffix).status_code == 422


def test_detection_filters_dates_and_assignment_revocation(data):
    with Session(data[0]) as db, db.begin():
        for n in range(3):
            evaluate_detection_rules(db, audit(db, n=n))
    client = login(data, "admin")
    events = client.get("/monitoring/detections?severity=HIGH&event_type=REPEATED_DENIED_ACCESS").json()
    assert events["total"] == 1 and events["items"][0]["evidence"]
    after = (AT + timedelta(days=1)).isoformat()
    assert client.get("/monitoring/timeline", params={"start": after, "category": "ACCESS_DENIED"}).json()["total"] == 0
    with Session(data[0]) as db, db.begin():
        assignment = db.scalar(select(DepartmentAdminAssignment))
        assignment.revoked_at = datetime.now(timezone.utc); assignment.revoked_by = "super"
    assert client.get("/monitoring/timeline").status_code == 403


def test_global_auth_activity_and_safe_context_allowlist(data):
    with Session(data[0]) as db, db.begin():
        db.add(AuditEvent(actor_id="employee", action="AUTH_MFA_VERIFIED", outcome="ALLOW", timestamp=AT,
            context_data={"raw_token": "NEVER-EXPOSE-RAW-TOKEN", "secret": "NEVER-EXPOSE-SECRET", "session_ref": "NOT-A-SAFE-SESSION-REFERENCE"}))
    client = login(data, "super")
    result = client.get("/monitoring/timeline?category=AUDIT_EVENT").json()
    assert result["total"] == 1
    assert "NEVER-EXPOSE" not in str(result) and result["items"][0]["session_ref"] is None
    assert login(data, "admin").get("/monitoring/timeline?category=AUDIT_EVENT").json()["total"] == 0


def test_cross_scope_risk_and_detection_absent_before_timeline_totals(data):
    with Session(data[0]) as db, db.begin():
        for n in range(3):
            evaluate_detection_rules(db, audit(db, n=n, department="other" if n == 2 else "dept"))
    client = login(data, "admin")
    for category in ("SECURITY_DETECTION", "RISK_ASSESSMENT"):
        scoped = client.get("/monitoring/timeline", params={"category": category}).json()
        global_result = login(data, "super").get("/monitoring/timeline", params={"category": category}).json()
        assert scoped["total"] < global_result["total"]
        client = login(data, "admin")
    with Session(data[0]) as db, db.begin():
        db.add(DepartmentAdminAssignment(user_id="admin", department_id="other", assigned_by="super"))
    assert client.get("/monitoring/timeline?category=SECURITY_DETECTION").json()["total"] > 0


def test_timeline_date_boundaries_and_postgresql_compilation(data):
    from sqlalchemy.dialects import postgresql
    from app.services.security_console import timeline_query
    with Session(data[0]) as db, db.begin():
        audit(db, n=0, at=AT)
        audit(db, n=1, at=AT + timedelta(hours=1))
        sql = str(select(timeline_query(db, "super")).compile(dialect=postgresql.dialect()))
        assert "UNION ALL" in sql and "data_disclosures" in sql and "risk_assessments" in sql
    result = login(data, "super").get("/monitoring/timeline", params={"category": "ACCESS_DENIED", "start": AT.isoformat(), "end": (AT+timedelta(hours=1)).isoformat()}).json()
    assert result["total"] == 1 and result["items"][0]["source_id"] == "audit-0"


def test_empty_scope_results_are_actual_zeroes(data):
    client = login(data, "super")
    result = client.get("/console/dashboard/security-overview").json()
    for key in ("detections", "high_detections", "critical_detections", "open_incidents", "disclosure_events", "distinct_records", "elevated_employees"):
        assert result[key] == 0
    assert result["recent_detections"] == result["recent_activity"] == result["employee_risks"] == []
