from sqlalchemy.orm import Session

from app.models.audit_event import AuditEvent
from app.models.incident import Incident
from app.models.incident_event import IncidentEvent
from app.models.security_event import SecurityEvent
from app.models.user import User
from app.schemas.ai import EvidenceItem
from app.services import administrative_access as admin


def get_audit_events(
    db: Session,
    user: User,
    resource_id: str | None = None,
    actor_id: str | None = None,
    action: str | None = None,
    outcome: str | None = None,
    limit: int = 10,
) -> list[AuditEvent]:
    query = admin.audit_query(db, user.id)
    for column, value in [(AuditEvent.resource_id, resource_id), (AuditEvent.actor_id, actor_id),
                          (AuditEvent.action, action), (AuditEvent.outcome, outcome)]:
        if value:
            query = query.filter(column == value)
    return query.order_by(AuditEvent.timestamp.desc()).limit(min(max(1, limit), 100)).all()


def get_security_events(
    db: Session,
    user: User,
    resource_id: str | None = None,
    actor_id: str | None = None,
    event_type: str | None = None,
    severity: str | None = None,
    limit: int = 10,
) -> list[SecurityEvent]:
    query = admin.security_query(db, user.id)
    for column, value in [(SecurityEvent.resource_id, resource_id), (SecurityEvent.actor_id, actor_id),
                          (SecurityEvent.event_type, event_type), (SecurityEvent.severity, severity)]:
        if value:
            query = query.filter(column == value)
    return query.order_by(SecurityEvent.timestamp.desc()).limit(min(max(1, limit), 100)).all()


def get_resource_activity(
    db: Session,
    user: User,
    resource_id: str,
    limit: int = 10,
) -> list[AuditEvent]:
    return get_audit_events(db=db, user=user, resource_id=resource_id, limit=limit)


def get_incident_evidence(
    db: Session,
    user: User,
    incident_id: str,
) -> list[EvidenceItem]:
    """
    Retrieve an incident and its associated security events and audit records
    only if authorized. Returns structured evidence items.
    """
    incident = get_incident(db, user, incident_id)
    if incident is None:
        return []

    evidence: list[EvidenceItem] = []

    # 1. Incident Evidence
    evidence.append(
        EvidenceItem(
            source_type="incident",
            source_id=incident.id,
            severity=incident.severity,
            timestamp=incident.created_at,
            description=f"Incident '{incident.title}' status is {incident.status}.",
            details={
                "title": incident.title,
                "status": incident.status,
                "severity": incident.severity,
                "resource_id": incident.resource_id,
                "assigned_to_id": incident.assigned_to_id,
            },
        )
    )

    # 2. Linked Security Events
    linked_sec_events = (
        admin.security_query(db, user.id)
        .join(IncidentEvent, IncidentEvent.security_event_id == SecurityEvent.id)
        .filter(IncidentEvent.incident_id == incident.id)
        .all()
    )

    processed_audit_ids: set[str] = set()

    for sec in linked_sec_events:
        evidence.append(
            EvidenceItem(
                source_type="security_event",
                source_id=sec.id,
                event_type=sec.event_type,
                severity=sec.severity,
                timestamp=sec.timestamp,
                description=sec.description,
                details={"actor_id": sec.actor_id, "resource_id": sec.resource_id},
            )
        )

        # 3. Linked Source Audit Event (via source_audit_id)
        if sec.source_audit_id and sec.source_audit_id not in processed_audit_ids:
            audit = admin.audit_query(db, user.id).filter(AuditEvent.id == sec.source_audit_id).first()
            if audit is not None:
                evidence.append(
                    EvidenceItem(
                        source_type="audit_event",
                        source_id=audit.id,
                        action=audit.action,
                        outcome=audit.outcome,
                        reason=audit.reason,
                        timestamp=audit.timestamp,
                        description=f"Audit event '{audit.action}' with outcome '{audit.outcome}' linked to security event.",
                        details=audit.context_data or {},
                    )
                )
                processed_audit_ids.add(audit.id)

    return evidence


def get_incident(db: Session, user: User, incident_id: str) -> Incident | None:
    return admin.incident_query(db, user.id).filter(Incident.id == incident_id).first()


def get_recent_incidents(db: Session, user: User, limit: int = 10) -> list[Incident]:
    return admin.incident_query(db, user.id).order_by(Incident.created_at.desc()).limit(min(max(1, limit), 100)).all()


def get_recent_security_events(db: Session, user: User, limit: int = 10) -> list[SecurityEvent]:
    return get_security_events(db=db, user=user, limit=limit)


def get_recent_audit_events(db: Session, user: User, limit: int = 10) -> list[AuditEvent]:
    return get_audit_events(db=db, user=user, limit=limit)


def get_resource_security_activity(
    db: Session, user: User, resource_id: str, limit: int = 10
) -> list[AuditEvent]:
    return get_resource_activity(db=db, user=user, resource_id=resource_id, limit=limit)
