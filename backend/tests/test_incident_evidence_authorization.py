"""Stage 4B: complete investigative scope on incident mutations, memory only."""
from datetime import datetime, timezone

import pytest
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.models import AuditEvent, DepartmentAdminAssignment, Incident, IncidentEvent, MonitoringScope, SecurityEvent
from app.services import organization_authority as authority
from tests.test_exposure import data, login
from tests.test_mfa_workflows import world, post


@pytest.fixture
def evidence(data):
    with Session(data[0]) as db, db.begin():
        db.add_all([
            SecurityEvent(id="a-visible", actor_id="employee", resource_id="r", event_type="FIXTURE", severity="HIGH", description="Fictional A evidence", evidence={"rule": "FIXTURE"}),
            SecurityEvent(id="z-cross", actor_id="employee", resource_id="r", event_type="FIXTURE", severity="HIGH", description="Fictional A/B evidence", evidence={"rule": "FIXTURE"}),
        ])
        db.flush()
        db.add_all([
            MonitoringScope(security_event_id="a-visible", department_id="dept"),
            MonitoringScope(security_event_id="z-cross", department_id="dept"),
            MonitoringScope(security_event_id="z-cross", department_id="other"),
        ])
    return data


def create(client, ids, assignee=None):
    return post(client, "/console/incidents", {
        "title": "Fictional scope regression", "description": "Synthetic evidence only",
        "severity": "HIGH", "resource_id": "r", "security_event_ids": ids,
        **({"assigned_to_id": assignee} if assignee else {}),
    })


def assert_no_mutation(engine):
    with Session(engine) as db:
        assert db.query(Incident).count() == 0
        assert db.query(IncidentEvent).count() == 0
        assert db.query(AuditEvent).filter(AuditEvent.action == "INCIDENT_CREATED").count() == 0


def assign_other(engine):
    with Session(engine) as db, db.begin():
        db.add(DepartmentAdminAssignment(user_id="admin", department_id="other", assigned_by="super"))


def test_exact_audit_reproduction_rejects_hidden_cross_department_evidence(evidence):
    client = login(evidence, "admin")
    visible = client.get("/monitoring/detections").json()["items"]
    assert {e["id"] for e in visible} == {"a-visible"}
    result = create(client, ["z-cross"])
    assert result.status_code == 403, result.text
    assert_no_mutation(evidence[0])


@pytest.mark.parametrize("actor,both", [("admin", True), ("super", False)])
def test_complete_scope_and_super_admin_remain_authorized(evidence, actor, both):
    if both:
        assign_other(evidence[0])
    client = login(evidence, actor)
    result = create(client, ["a-visible", "z-cross", "z-cross"], assignee=actor)
    assert result.status_code == 201, result.text
    with Session(evidence[0]) as db:
        assert db.query(Incident).count() == 1
        assert db.query(IncidentEvent).count() == 2
    assert client.get("/console/incidents/" + result.json()["id"]).status_code == 200


def test_mixed_evidence_rejects_entire_creation(evidence):
    client = login(evidence, "admin")
    assert create(client, ["a-visible", "z-cross"]).status_code == 403
    assert_no_mutation(evidence[0])


def test_reassignment_is_respected_without_new_login(evidence):
    assign_other(evidence[0])
    client = login(evidence, "admin")
    assert "z-cross" in {e["id"] for e in client.get("/monitoring/detections").json()["items"]}
    with Session(evidence[0]) as db, db.begin():
        row = db.scalar(select(DepartmentAdminAssignment).where(DepartmentAdminAssignment.department_id == "other"))
        row.revoked_at = datetime.now(timezone.utc); row.revoked_by = "super"
    assert create(client, ["z-cross"]).status_code == 403
    assert_no_mutation(evidence[0])


@pytest.mark.parametrize("change", ["revoke", "demote"])
def test_authority_revalidated_at_evidence_department_lock(evidence, monkeypatch, change):
    assign_other(evidence[0])
    client = login(evidence, "admin")
    original = authority.revalidate_authority_for_mutation
    changed = []
    def interleave(tx, actor_id, action, scope=None):
        if actor_id == "admin" and isinstance(scope, authority.DepartmentScope) and scope.department_id == "other" and not changed:
            changed.append(True)
            if change == "revoke":
                tx.execute(text("UPDATE department_admin_assignments SET revoked_at=:now, revoked_by='super' WHERE user_id='admin' AND department_id='other'"), {"now": datetime.now(timezone.utc).isoformat(sep=" ")})
            else:
                tx.execute(text("UPDATE users SET organization_role='EMPLOYEE' WHERE id='admin'"))
        return original(tx, actor_id, action, scope)
    monkeypatch.setattr(authority, "revalidate_authority_for_mutation", interleave)
    assert create(client, ["z-cross"]).status_code == 403
    assert changed == [True]
    assert_no_mutation(evidence[0])


def test_assignee_requires_all_evidence_departments(evidence):
    client = login(evidence, "super")
    assert create(client, ["z-cross"], assignee="admin").status_code == 403
    assert_no_mutation(evidence[0])


@pytest.mark.parametrize("scope_state", ["missing", "unknown"])
def test_incomplete_new_detection_scope_fails_closed(evidence, scope_state):
    with Session(evidence[0]) as db, db.begin():
        db.add(SecurityEvent(id="incomplete", actor_id="employee", resource_id="r", event_type="FIXTURE", severity="HIGH", description="Fictional incomplete evidence", evidence={"rule": "FIXTURE"}))
        db.flush()
        if scope_state == "unknown":
            db.add(MonitoringScope(security_event_id="incomplete", department_id=None))
    assert create(login(evidence, "admin"), ["incomplete"]).status_code == 403
    assert_no_mutation(evidence[0])
