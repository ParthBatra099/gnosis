from datetime import datetime, timedelta, timezone
import logging
from sqlalchemy.orm import Session

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
    """
    Evaluates deterministic security rules against incoming audit events.
    Failsafe: Never raises exceptions or affects upstream workflow execution.
    """
    security_events: list[SecurityEvent] = []
    try:
        now = datetime.now(timezone.utc)

        # Rule 1: REPEATED_DENIED_ACCESS (>= 3 RESOURCE_ACCESS_DENIED in last 15 min)
        if (
            audit_event.action == "RESOURCE_ACCESS"
            and audit_event.outcome == "DENY"
            and audit_event.actor_id
        ):
            time_window = now - timedelta(minutes=15)
            denied_count = (
                db.query(AuditEvent)
                .filter(
                    AuditEvent.actor_id == audit_event.actor_id,
                    AuditEvent.action == "RESOURCE_ACCESS",
                    AuditEvent.outcome == "DENY",
                    AuditEvent.timestamp >= time_window,
                )
                .count()
            )
            if denied_count >= 3:
                sec_event = SecurityEvent(
                    event_type="REPEATED_DENIED_ACCESS",
                    severity="HIGH",
                    actor_id=audit_event.actor_id,
                    resource_id=audit_event.resource_id,
                    source_audit_id=audit_event.id,
                    description=f"Actor {audit_event.actor_id} breached threshold with {denied_count} denied access attempts in 15 minutes.",
                )
                db.add(sec_event)
                db.flush()
                _escalate_security_event_to_incident(db, sec_event)
                security_events.append(sec_event)

        # Rule 2: CRITICAL_RESOURCE_ACCESS
        if audit_event.resource_id:
            resource = db.query(Resource).filter(Resource.id == audit_event.resource_id).first()
            if resource and resource.sensitivity == "CRITICAL":
                severity = "CRITICAL" if audit_event.outcome == "DENY" else "MEDIUM"
                sec_event = SecurityEvent(
                    event_type="CRITICAL_RESOURCE_ACCESS",
                    severity=severity,
                    actor_id=audit_event.actor_id,
                    resource_id=audit_event.resource_id,
                    source_audit_id=audit_event.id,
                    description=f"CRITICAL resource '{resource.name}' access attempt with outcome '{audit_event.outcome}'.",
                )
                db.add(sec_event)
                db.flush()
                _escalate_security_event_to_incident(db, sec_event)
                security_events.append(sec_event)

        # Rule 3: CROSS_DEPARTMENT_ANOMALY
        if (
            audit_event.action == "RESOURCE_ACCESS"
            and audit_event.outcome == "DENY"
            and audit_event.reason == "DENY_DEPARTMENT_MISMATCH"
            and audit_event.actor_id
        ):
            time_window = now - timedelta(minutes=10)
            distinct_denied_resources = (
                db.query(AuditEvent.resource_id)
                .filter(
                    AuditEvent.actor_id == audit_event.actor_id,
                    AuditEvent.action == "RESOURCE_ACCESS",
                    AuditEvent.outcome == "DENY",
                    AuditEvent.reason == "DENY_DEPARTMENT_MISMATCH",
                    AuditEvent.timestamp >= time_window,
                )
                .distinct()
                .count()
            )
            if distinct_denied_resources >= 2:
                sec_event = SecurityEvent(
                    event_type="CROSS_DEPARTMENT_ANOMALY",
                    severity="HIGH",
                    actor_id=audit_event.actor_id,
                    resource_id=audit_event.resource_id,
                    source_audit_id=audit_event.id,
                    description=f"Actor {audit_event.actor_id} probed {distinct_denied_resources} distinct cross-department resources within 10 minutes.",
                )
                db.add(sec_event)
                db.flush()
                _escalate_security_event_to_incident(db, sec_event)
                security_events.append(sec_event)

        # Rule 4: AFTER_HOURS_ACCESS
        event_time = audit_event.timestamp
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=timezone.utc)

        hour = event_time.hour
        if hour >= 22 or hour < 5:
            if audit_event.action == "RESOURCE_ACCESS" and audit_event.outcome == "ALLOW":
                sec_event = SecurityEvent(
                    event_type="AFTER_HOURS_ACCESS",
                    severity="LOW",
                    actor_id=audit_event.actor_id,
                    resource_id=audit_event.resource_id,
                    source_audit_id=audit_event.id,
                    description=f"Resource access observed outside operating window (22:00-05:00 UTC) at hour {hour}.",
                )
                db.add(sec_event)
                db.flush()
                _escalate_security_event_to_incident(db, sec_event)
                security_events.append(sec_event)

        db.commit()
    except Exception as err:
        logger.error(f"Detection engine error: {err}")
        db.rollback()

    return security_events