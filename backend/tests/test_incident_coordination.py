"""Deterministic interleavings on isolated SQLite; not PG row-lock proofs."""
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import event, select, update
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.models import AuditEvent, Incident, IncidentEvent, MonitoringScope, SecurityEvent
from app.security import detection_engine as detection
from app.services import administrative_access as admin, incident_coordination as coordination
from app.services import organization_authority as authority
from tests.test_exposure import data, login
from tests.test_mfa_workflows import world, post
from tests.test_incident_evidence_authorization import evidence, create, assert_no_mutation


def seed_incident(engine):
    with Session(engine) as db, db.begin():
        db.add(Incident(id="incident", title="Fictional", description="Synthetic evidence",
                        severity="HIGH", status="OPEN",
                        reporter_id="employee", resource_id="r"))


def test_ordered_parent_locks_precede_validation_and_no_evidence_locks(evidence, monkeypatch):
    sql = []
    def capture(state):
        if state.is_select and state.statement._for_update_arg is not None:
            sql.append(str(state.statement.compile(dialect=postgresql.dialect())))
    original = admin.lock_resource_authority
    def validate(*args):
        parents = [s for s in sql if "FROM users " in s or "FROM departments " in s]
        assert "FROM users ORDER BY users.id FOR NO KEY UPDATE" in parents[0]
        assert "FROM departments ORDER BY departments.id FOR NO KEY UPDATE" in parents[1]
        return original(*args)
    monkeypatch.setattr(admin, "lock_resource_authority", validate)
    event.listen(Session, "do_orm_execute", capture)
    try:
        # Super Admin sorts after the target employee; lock order is not actor-first.
        assert create(login(evidence, "super"), ["a-visible"], "admin").status_code == 201
    finally:
        event.remove(Session, "do_orm_execute", capture)
    assert all(not any(f"FROM {table}" in s for table in (
        "resources", "audit_events", "security_events", "monitoring_scopes")) for s in sql)


def test_escalation_rechecks_status_after_wait(evidence, monkeypatch):
    seed_incident(evidence[0])
    original = detection.lock_incident_row
    calls = []
    def after_wait(db, incident_id):
        calls.append(incident_id)
        # Deterministic model of a manual transition winning the parent lock.
        db.execute(update(Incident).where(Incident.id == incident_id).values(status="RESOLVED")
                   .execution_options(synchronize_session=False))
        return original(db, incident_id)
    monkeypatch.setattr(detection, "lock_incident_row", after_wait)
    with Session(evidence[0], autoflush=False) as db, db.begin():
        detection._escalate_security_event_to_incident(db, db.get(SecurityEvent, "a-visible"))
    assert calls == ["incident"]
    with Session(evidence[0]) as db:
        link = db.query(IncidentEvent).one()
        assert link.incident_id != "incident"
        assert db.get(Incident, "incident").status == "RESOLVED"


@pytest.mark.parametrize("winner", ["manual", "automatic"])
def test_attachment_rechecks_link_after_other_writer_wins(evidence, monkeypatch, winner):
    seed_incident(evidence[0])
    if winner == "manual":
        original = detection.lock_incident_row
        def after_wait(db, incident_id):
            # Other writer's committed linkage is visible when lock is acquired.
            coordination.attach_events(db, db.get(Incident, incident_id), ["a-visible"])
            return original(db, incident_id)
        monkeypatch.setattr(detection, "lock_incident_row", after_wait)
        with Session(evidence[0], autoflush=False) as db, db.begin():
            detection._escalate_security_event_to_incident(db, db.get(SecurityEvent, "a-visible"))
    else:
        original = admin.lock_incident_row
        def after_wait(db, incident_id):
            detection._escalate_security_event_to_incident(db, db.get(SecurityEvent, "a-visible"))
            return original(db, incident_id)
        monkeypatch.setattr(admin, "lock_incident_row", after_wait)
        result = post(login(evidence, "super"), "/console/incidents/incident/events",
                      {"security_event_ids": ["a-visible", "a-visible"]})
        assert result.status_code == 200, result.text
    with Session(evidence[0]) as db:
        assert db.query(IncidentEvent).count() == 1


def test_repeated_escalation_and_pending_links_are_idempotent(evidence):
    with Session(evidence[0], autoflush=False) as db, db.begin():
        sec = db.get(SecurityEvent, "a-visible")
        detection._escalate_security_event_to_incident(db, sec)
        detection._escalate_security_event_to_incident(db, sec)
        detection._escalate_security_event_to_incident(db, db.get(SecurityEvent, "z-cross"))
    with Session(evidence[0]) as db:
        assert db.query(Incident).count() == 1
        assert db.query(IncidentEvent).count() == 2


def test_advisory_lock_is_stable_transaction_scoped_and_failures_propagate():
    statements = []
    class DB:
        def in_transaction(self): return True
        def get_bind(self): return SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))
        def execute(self, statement): statements.append(statement)
    db = DB()
    coordination.serialize_escalation(db)
    coordination.serialize_escalation(db)
    compiled = statements[0].compile(dialect=postgresql.dialect())
    assert "pg_advisory_xact_lock" in str(compiled)
    assert list(compiled.params.values()) == [0x474E4F53, 0x494E4344]
    assert statements[1].compile().params == statements[0].compile().params
    db.in_transaction = lambda: False
    with pytest.raises(RuntimeError): coordination.serialize_escalation(db)


def test_advisory_failure_precedes_evidence_insertion(evidence, monkeypatch):
    def timeout(db): raise OperationalError("hidden", {}, Exception("synthetic timeout"))
    monkeypatch.setattr(detection, "serialize_escalation", timeout)
    with Session(evidence[0]) as db:
        with pytest.raises(OperationalError), db.begin():
            detection.emit(db, actor_id="employee", rule="FIXTURE", severity="HIGH", resource_id="r",
                audit_id=None, at=datetime.now(timezone.utc), start=datetime.now(timezone.utc),
                threshold=3, count=3, evidence={}, departments={"dept"})
    with Session(evidence[0]) as db:
        assert db.query(SecurityEvent).count() == 2
        assert db.query(Incident).count() == 0


@pytest.mark.parametrize("failure", ["scope", "link"])
def test_failed_publication_rolls_back_event_scopes_and_incident(evidence, monkeypatch, failure):
    with Session(evidence[0]) as db:
        before = db.query(MonitoringScope).count()
    if failure == "scope":
        original = detection.add_scopes
        def fail(db, departments, **kwargs):
            original(db, departments, **kwargs)
            raise RuntimeError("scope publication failure")
        monkeypatch.setattr(detection, "add_scopes", fail)
    else:
        original = detection.attach_events
        def fail(db, incident, ids):
            original(db, incident, ids)
            raise RuntimeError("link publication failure")
        monkeypatch.setattr(detection, "attach_events", fail)
    with Session(evidence[0]) as db:
        with pytest.raises(RuntimeError), db.begin():
            detection.emit(db, actor_id="employee", rule="ROLLBACK", severity="HIGH", resource_id="r",
                audit_id=None, at=datetime.now(timezone.utc), start=datetime.now(timezone.utc),
                threshold=3, count=3, evidence={}, departments={"dept", "other"})
    with Session(evidence[0]) as db:
        assert db.query(SecurityEvent).count() == 2
        assert db.query(MonitoringScope).count() == before
    assert_no_mutation(evidence[0])


def test_successful_publication_includes_all_scopes(evidence):
    with Session(evidence[0]) as db, db.begin():
        sec = detection.emit(db, actor_id="employee", rule="COMPLETE", severity="HIGH", resource_id="r",
            audit_id=None, at=datetime.now(timezone.utc), start=datetime.now(timezone.utc),
            threshold=3, count=3, evidence={}, departments={"dept", "other"})
        event_id = sec.id
    with Session(evidence[0]) as db:
        assert set(db.scalars(select(MonitoringScope.department_id).where(
            MonitoringScope.security_event_id == event_id))) == {"dept", "other"}


def test_parent_lock_timeout_rolls_back_manual_mutation(evidence, monkeypatch):
    seed_incident(evidence[0])
    def timeout(*args): raise OperationalError("hidden", {}, Exception("synthetic lock timeout"))
    monkeypatch.setattr(admin, "lock_incident_row", timeout)
    with pytest.raises(OperationalError):
        post(login(evidence, "super"), "/console/incidents/incident/events", {"security_event_ids": ["a-visible"]})
    with Session(evidence[0]) as db:
        assert db.query(IncidentEvent).count() == 0
        assert db.query(AuditEvent).filter(AuditEvent.action == "INCIDENT_EVENTS_ATTACHED").count() == 0
        assert db.get(Incident, "incident").status == "OPEN"


def test_audit_failure_rolls_back_already_flushed_link(evidence, monkeypatch):
    seed_incident(evidence[0])
    def fail(*args, **kwargs): raise RuntimeError("synthetic audit failure")
    monkeypatch.setattr(admin, "append_audit", fail)
    with pytest.raises(RuntimeError):
        post(login(evidence, "super"), "/console/incidents/incident/events", {"security_event_ids": ["a-visible"]})
    with Session(evidence[0]) as db:
        assert db.query(IncidentEvent).count() == 0


def test_lock_refresh_rejects_newly_out_of_scope_membership(evidence, monkeypatch):
    seed_incident(evidence[0])
    original = admin.lock_incident_row
    def after_wait(db, incident_id):
        coordination.attach_events(db, db.get(Incident, incident_id), ["z-cross"])
        return original(db, incident_id)
    monkeypatch.setattr(admin, "lock_incident_row", after_wait)
    result = post(login(evidence, "admin"), "/console/incidents/incident/events", {"security_event_ids": ["a-visible"]})
    assert result.status_code == 404
    with Session(evidence[0]) as db:
        assert db.query(IncidentEvent).count() == 0


def test_concurrent_find_or_create_uses_transaction_coordination(evidence, monkeypatch):
    """Emulate only PG's advisory mutex; real SQLite service writes run serially.

    This verifies callers retain coordination through commit, not PG lock semantics.
    """
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event, Lock
    mutex = Lock()
    first_entered, second_waiting, release_first = Event(), Event(), Event()
    order = []
    class AdvisoryConnection:
        def in_transaction(self): return True
        def get_bind(self): return SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))
        def execute(self, statement):
            assert "pg_advisory_xact_lock" in str(statement)
            if first_entered.is_set(): second_waiting.set()
            assert mutex.acquire(timeout=5)
    def emulate(db):
        if not db.info.get("emulated_incident_lock"):
            coordination.serialize_escalation(AdvisoryConnection())
            db.info["emulated_incident_lock"] = True
    monkeypatch.setattr(detection, "serialize_escalation", emulate)
    def worker(event_id, first=False):
        with Session(evidence[0], autoflush=False) as db:
            try:
                with db.begin():
                    detection.serialize_escalation(db)
                    if first:
                        first_entered.set()
                        assert release_first.wait(5)
                    detection._escalate_security_event_to_incident(db, db.get(SecurityEvent, event_id))
                    order.append("write:" + event_id)
                order.append("commit:" + event_id)
            finally:
                if db.info.get("emulated_incident_lock"):
                    order.append("release:" + event_id)
                    mutex.release()
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(worker, "a-visible", True)
        assert first_entered.wait(5)
        second = executor.submit(worker, "z-cross")
        try:
            assert second_waiting.wait(5)
            assert not second.done()
        finally:
            release_first.set()
        first.result(timeout=10)
        second.result(timeout=10)
    assert order == ["write:a-visible", "commit:a-visible", "release:a-visible",
                     "write:z-cross", "commit:z-cross", "release:z-cross"]
    with Session(evidence[0]) as db:
        assert db.query(Incident).count() == 1
        assert db.query(IncidentEvent).count() == 2


def test_department_lock_cache_is_transaction_bound(evidence):
    statements = []
    def capture(state):
        if state.is_select and state.statement._for_update_arg is not None:
            statements.append(str(state.statement.compile(dialect=postgresql.dialect())))
    with Session(evidence[0]) as db:
        with db.begin() as old:
            db.info["incident_locked_departments"] = (old, frozenset({"dept"}))
        event.listen(db, "do_orm_execute", capture)
        with db.begin():
            assert authority.revalidate_authority_for_mutation(db, "admin",
                admin.A.DEPARTMENT_INCIDENT_INVESTIGATE, authority.DepartmentScope("dept")).allowed
    assert any("FROM departments" in s and s.endswith("FOR UPDATE") for s in statements)


def test_two_investigators_recheck_same_link_after_wait(evidence, monkeypatch):
    seed_incident(evidence[0])
    original = admin.lock_incident_row
    def after_wait(db, incident_id):
        # Model the first investigator completing before the second acquires lock.
        coordination.attach_events(db, db.get(Incident, incident_id), ["a-visible"])
        return original(db, incident_id)
    monkeypatch.setattr(admin, "lock_incident_row", after_wait)
    result = post(login(evidence, "admin"), "/console/incidents/incident/events",
                  {"security_event_ids": ["a-visible"]})
    assert result.status_code == 200
    with Session(evidence[0]) as db:
        assert db.query(IncidentEvent).count() == 1


def test_commit_failure_rolls_back_mutation_and_audit(evidence):
    seed_incident(evidence[0])
    client = login(evidence, "super")
    def fail_commit(db):
        if db.info.get("incident_locked_departments"):
            raise RuntimeError("synthetic commit failure")
    event.listen(Session, "before_commit", fail_commit)
    try:
        with pytest.raises(RuntimeError, match="synthetic commit failure"):
            post(client, "/console/incidents/incident/events", {"security_event_ids": ["a-visible"]})
    finally:
        event.remove(Session, "before_commit", fail_commit)
    with Session(evidence[0]) as db:
        assert db.query(IncidentEvent).count() == 0
        assert db.query(AuditEvent).filter(AuditEvent.action == "INCIDENT_EVENTS_ATTACHED").count() == 0
