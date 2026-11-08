from datetime import datetime, timedelta, timezone
import logging
from sqlalchemy.orm import Session
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from app.security import risk_scoring as policy
from app.services.risk_service import snapshot, add_scopes, persist_assessment, utc, digest

from app.models.audit_event import AuditEvent
from app.models.incident import Incident
from app.models.incident_event import IncidentEvent
from app.models.resource import Resource
from app.models.security_event import SecurityEvent

logger = logging.getLogger("gnosis.detection")


def _escalate_security_event_to_incident(db: Session, sec_event: SecurityEvent) -> None:
    """Escalates HIGH or CRITICAL security events to an Incident in a deterministic manner."""
    if sec_event.severity not in {"HIGH", "CRITICAL"}:
        return

    # Look for active OPEN or INVESTIGATING incident matching actor or resource
    query = db.query(Incident).filter(Incident.status.in_(["OPEN", "INVESTIGATING"]))
    if sec_event.resource_id:
        query = query.filter(Incident.resource_id == sec_event.resource_id)
    elif sec_event.actor_id:
        query = query.filter(Incident.reporter_id == sec_event.actor_id)

    existing_incident = query.order_by(Incident.created_at.desc()).first()

    if existing_incident:
        target_incident = existing_incident
    else:
        target_incident = Incident(
            title=f"Automated Escalation: {sec_event.event_type}",
            description=sec_event.description,
            severity=sec_event.severity,
            status="OPEN",
            reporter_id=sec_event.actor_id,
            resource_id=sec_event.resource_id,
        )
        db.add(target_incident)
        db.flush()

    # Avoid duplicate IncidentEvent linkages
    link_exists = (
        db.query(IncidentEvent)
        .filter(
            IncidentEvent.incident_id == target_incident.id,
            IncidentEvent.security_event_id == sec_event.id,
        )
        .first()
    )
    if not link_exists:
        inc_event = IncidentEvent(
            incident_id=target_incident.id,
            security_event_id=sec_event.id,
        )
        db.add(inc_event)


def evaluate_detection_rules(db: Session, audit_event: AuditEvent) -> list[SecurityEvent]:
    """Flush only: caller owns commit/rollback. Non-resource actions are irrelevant."""
    if audit_event.action != "RESOURCE_ACCESS" or audit_event.outcome not in {"ALLOW", "DENY"}:
        return []
    return observe(db, actor_id=audit_event.actor_id, at=audit_event.timestamp, audit=audit_event)


def evaluate_disclosure_rules(db: Session, response_id: str) -> list[SecurityEvent]:
    """Process committed application evidence; no ALLOW-to-disclosure inference."""
    from sqlalchemy import select
    from app.models import DataDisclosure
    rows = db.scalars(select(DataDisclosure).where(DataDisclosure.response_id == response_id)).all()
    if not rows:
        return []
    return observe(db, actor_id=rows[0].actor_id, at=max(row.timestamp for row in rows), response_id=response_id)


def emit(db, *, actor_id, rule, severity, resource_id, audit_id, at, start, threshold, count,
         evidence, departments, response_id=None, session_ref=None):
    bucket = int(at.timestamp()) // (policy.WINDOW_MINUTES * 60)
    # A later denial must not be suppressed by an earlier allowed critical access.
    # Severity transitions are bounded; critical resources retain separate episodes.
    key = digest([policy.POLICY_VERSION, actor_id, rule, severity,
                  resource_id if rule == "CRITICAL_RESOURCE_ACCESS" else None, bucket])
    existing = db.scalar(select(SecurityEvent).where(SecurityEvent.episode_key == key))
    if existing:
        return None
    description = f"{rule}: observed {count}; threshold {threshold}. Review evidence; no permission change."
    event = SecurityEvent(episode_key=key, event_type=rule, severity=severity, actor_id=actor_id,
        resource_id=resource_id, source_audit_id=audit_id, timestamp=at, description=description,
        evidence={**evidence, "rule": rule, "policy_version": policy.POLICY_VERSION,
                  "window_start": start.isoformat(), "window_end": at.isoformat(),
                  "threshold": threshold, "count": count, "response_id": response_id, "session_ref": session_ref})
    try:
        with db.begin_nested():
            db.add(event)
            db.flush()
            add_scopes(db, departments, event_id=event.id)
            _escalate_security_event_to_incident(db, event)
    except IntegrityError:
        # Only a proven competing episode is a safe duplicate; other errors propagate.
        if db.scalar(select(SecurityEvent.id).where(SecurityEvent.episode_key == key)):
            return None
        raise
    return event


def observe(db, *, actor_id, at, audit=None, response_id=None):
    if not actor_id:
        return []
    at = utc(at)
    start = at - timedelta(minutes=policy.WINDOW_MINUTES)
    data = snapshot(db, actor_id, start, at)
    metrics, evidence, departments, audits, disclosures = data
    trigger_context = audit.context_data or {} if audit else {}
    request_key = response_id or trigger_context.get("response_id") or (audit.id if audit else None)
    matching = [d for d in disclosures if d.response_id == response_id] if response_id else []
    session_ref = matching[0].session_ref if matching else trigger_context.get("session_ref")
    resource_id = matching[0].resource_id if matching else audit.resource_id if audit else None
    rules = []
    if audit and audit.outcome == "DENY" and metrics["denials"] >= policy.DENIAL_THRESHOLD:
        rules.append(("REPEATED_DENIED_ACCESS", "HIGH", metrics["denials"], policy.DENIAL_THRESHOLD, data, start))
    if audit:
        resource = db.get(Resource, audit.resource_id) if audit.resource_id else None
        sensitivity = trigger_context.get("sensitivity") or (resource.sensitivity if resource else None)
        if sensitivity == "CRITICAL":
            rules.append(("CRITICAL_RESOURCE_ACCESS", "CRITICAL" if audit.outcome == "DENY" else "MEDIUM", 1, 1, data, start))
        cross_start = at - timedelta(minutes=10)
        cross_data = snapshot(db, actor_id, cross_start, at)
        cross = [a for a in cross_data[3] if a.outcome == "DENY" and a.reason == "DENY_DEPARTMENT_MISMATCH"]
        count = len({a.resource_id for a in cross if a.resource_id})
        if audit.outcome == "DENY" and audit.reason == "DENY_DEPARTMENT_MISMATCH" and count >= 2:
            rules.append(("CROSS_DEPARTMENT_ANOMALY", "HIGH", count, 2, cross_data, cross_start))
        if audit.outcome == "ALLOW" and (at.hour >= 22 or at.hour < 5):
            rules.append(("AFTER_HOURS_ACCESS", "LOW", 1, 1, data, start))
    if response_id:
        if metrics["sensitive_responses"] >= policy.SENSITIVE_THRESHOLD:
            rules.append(("REPEATED_SENSITIVE_DISCLOSURE", "HIGH", metrics["sensitive_responses"], policy.SENSITIVE_THRESHOLD, data, start))
        if metrics["distinct_records"] >= policy.BULK_THRESHOLD:
            rules.append(("BULK_DATA_DISCLOSURE", "HIGH", metrics["distinct_records"], policy.BULK_THRESHOLD, data, start))
    if audit and trigger_context.get("representation") == "business_records" and metrics["business_attempts"] >= policy.FREQUENCY_THRESHOLD:
        rules.append(("REQUEST_FREQUENCY_ANOMALY", "MEDIUM", metrics["business_attempts"], policy.FREQUENCY_THRESHOLD, data, start))
    if metrics["departments"] >= policy.DEPARTMENT_THRESHOLD:
        # Legitimate granted cross-department activity is a review signal, not a violation.
        severity = "HIGH" if metrics["denials"] >= policy.DENIAL_THRESHOLD else "LOW"
        rules.append(("DEPARTMENT_HOPPING", severity, metrics["departments"], policy.DEPARTMENT_THRESHOLD, data, start))
    emitted = []
    for rule, severity, count, threshold, supporting, window_start in rules:
        event = emit(db, actor_id=actor_id, rule=rule, severity=severity, resource_id=resource_id,
            audit_id=audit.id if audit else None, at=at, start=window_start, threshold=threshold, count=count,
            evidence=supporting[1], departments=supporting[2], response_id=response_id, session_ref=session_ref)
        if event:
            emitted.append(event)
    # Assess after detection so existing severity is represented, with full scope provenance.
    persist_assessment(db, actor_id, "EMPLOYEE", actor_id, at, start, snapshot(db, actor_id, start, at))
    if request_key:
        persist_assessment(db, actor_id, "REQUEST", request_key, at, start,
                           snapshot(db, actor_id, start, at, request_key=request_key))
    if session_ref:
        persist_assessment(db, actor_id, "SESSION", session_ref, at, start,
                           snapshot(db, actor_id, start, at, session_ref=session_ref))
    return emitted
