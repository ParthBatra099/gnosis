"""Database evidence adapter for the existing detection engine; never enforcement."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import AuditEvent, DataDisclosure, MonitoringScope, Resource, RiskAssessment, SecurityEvent
from app.security import risk_scoring as policy


def utc(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def snapshot(db, actor_id, start, end, *, request_key=None, session_ref=None):
    audits = db.scalars(select(AuditEvent).where(AuditEvent.actor_id == actor_id,
        AuditEvent.action == "RESOURCE_ACCESS", AuditEvent.timestamp >= start, AuditEvent.timestamp <= end)
        .order_by(AuditEvent.timestamp, AuditEvent.id)).all()
    disclosures = db.scalars(select(DataDisclosure).where(DataDisclosure.actor_id == actor_id,
        DataDisclosure.timestamp >= start, DataDisclosure.timestamp <= end,
        DataDisclosure.completion_state == "APPLICATION_COMPLETE")
        .order_by(DataDisclosure.timestamp, DataDisclosure.id)).all()
    events = db.scalars(select(SecurityEvent).where(SecurityEvent.actor_id == actor_id,
        SecurityEvent.timestamp >= start, SecurityEvent.timestamp <= end)
        .order_by(SecurityEvent.timestamp, SecurityEvent.id)).all()
    if request_key:
        audits = [a for a in audits if (a.context_data or {}).get("response_id", a.id) == request_key]
        disclosures = [d for d in disclosures if d.response_id == request_key]
        audit_ids = {a.id for a in audits}
        events = [e for e in events if e.source_audit_id in audit_ids or (e.evidence or {}).get("response_id") == request_key]
    if session_ref:
        audits = [a for a in audits if (a.context_data or {}).get("session_ref") == session_ref]
        disclosures = [d for d in disclosures if d.session_ref == session_ref]
        audit_ids = {a.id for a in audits}
        events = [e for e in events if e.source_audit_id in audit_ids or (e.evidence or {}).get("session_ref") == session_ref]
    departments = {d.department_id for d in disclosures}
    departments.update((a.context_data or {}).get("department_id") for a in audits)
    activity_department_count = len(departments - {None})
    # Security evidence may itself combine multiple departments. Preserve all of them.
    for event in events:
        scopes = db.scalars(select(MonitoringScope.department_id).where(MonitoringScope.security_event_id == event.id)).all()
        departments.update(scopes or [None])
    sensitive = [d for d in disclosures if d.sensitivity in {"CONFIDENTIAL", "CRITICAL"}]
    ranks = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    metrics = {
        "sensitive": len(sensitive), "sensitive_responses": len({d.response_id for d in sensitive}),
        "distinct_records": len({d.record_id for d in disclosures}), "disclosure_events": len(disclosures),
        "business_attempts": sum((a.context_data or {}).get("representation") == "business_records" for a in audits),
        "denials": sum(a.outcome == "DENY" for a in audits),
        "departments": activity_department_count,
        "max_severity": max((e.severity for e in events), key=lambda x: ranks.get(x, 0), default="LOW"),
    }
    evidence = {"audit_ids": [a.id for a in audits], "disclosure_ids": [d.id for d in disclosures],
                "security_event_ids": [e.id for e in events], "metrics": metrics,
                "coverage": "INCOMPLETE_OR_UNCONFIRMED" if None in departments else "RECORDED_EVIDENCE_ONLY",
                "transport_state": "UNKNOWN"}
    return metrics, evidence, departments, audits, disclosures


def add_scopes(db, departments, *, event_id=None, assessment_id=None):
    for department_id in departments or {None}:
        db.add(MonitoringScope(security_event_id=event_id, assessment_id=assessment_id, department_id=department_id))
    db.flush()


def persist_assessment(db, actor_id, scope, scope_key, at, start, data):
    metrics, evidence, departments, _, _ = data
    result = policy.score_risk(metrics)
    key = digest([actor_id, scope, scope_key, start.isoformat(), at.isoformat(), evidence, result])
    existing = db.scalar(select(RiskAssessment).where(RiskAssessment.fingerprint == key))
    if existing:
        return existing
    assessment = RiskAssessment(fingerprint=key, actor_id=actor_id, scope=scope, scope_key=scope_key,
        timestamp=at, window_start=start, window_end=at, evidence=evidence, **result)
    try:
        with db.begin_nested():
            db.add(assessment); db.flush()
            add_scopes(db, departments, assessment_id=assessment.id)
    except IntegrityError:
        existing = db.scalar(select(RiskAssessment).where(RiskAssessment.fingerprint == key))
        if existing:
            return existing
        raise
    return assessment


def monitor_disclosure(source, response_id):
    """Best-effort post-commit observation; no failure can alter a captured response."""
    try:
        with Session(bind=source.get_bind(), autoflush=False) as db, db.begin():
            from app.security.detection_engine import evaluate_disclosure_rules
            evaluate_disclosure_rules(db, response_id)
    except Exception:
        # Never log driver exceptions: they may contain SQL parameters or payloads.
        logging.getLogger("gnosis.detection").error("Disclosure monitoring failed; ledger retained for explicit replay")
