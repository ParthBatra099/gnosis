from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.models.audit_event import AuditEvent
from app.models.incident import Incident
from app.models.incident_event import IncidentEvent
from app.models.resource import Resource
from app.models.security_event import SecurityEvent
from app.models.user import User
from app.schemas.ai import EvidenceItem


def _get_owned_resource_ids(db: Session, user: User) -> list[str]:
    """Helper to fetch resource IDs owned by the authenticated user."""
    return [r.id for r in db.query(Resource.id).filter(Resource.owner_id == user.id).all()]


def get_audit_events(
    db: Session,
    user: User,
    resource_id: str | None = None,
    actor_id: str | None = None,
    action: str | None = None,
    outcome: str | None = None,
    limit: int = 10,
) -> list[AuditEvent]:
    """
    Retrieve audit events strictly within the authenticated user's scope.
    Controlled filters supported: resource_id, actor_id, action, outcome, limit.
    """
    safe_limit = min(max(1, limit), 100)
    owned_ids = _get_owned_resource_ids(db, user)

    if resource_id:
        res = db.query(Resource).filter(Resource.id == resource_id).first()
        if not res:
            return []
        if res.owner_id == user.id:
            query = db.query(AuditEvent).filter(AuditEvent.resource_id == resource_id)
        else:
            # Non-owner querying a specific unowned resource -> only see self actions
            query = db.query(AuditEvent).filter(
                AuditEvent.resource_id == resource_id,
                AuditEvent.actor_id == user.id,
            )
    else:
        query = db.query(AuditEvent).filter(
            or_(
                AuditEvent.actor_id == user.id,
                AuditEvent.resource_id.in_(owned_ids),
            )
        )

    if actor_id:
        if actor_id != user.id and (not resource_id or resource_id not in owned_ids):
            # User cannot filter by another actor's activity unless they own the resource
            return []
        query = query.filter(AuditEvent.actor_id == actor_id)

    if action:
        query = query.filter(AuditEvent.action == action)
    if outcome:
        query = query.filter(AuditEvent.outcome == outcome)

    return query.order_by(AuditEvent.timestamp.desc()).limit(safe_limit).all()


def get_security_events(
    db: Session,
    user: User,
    resource_id: str | None = None,
    actor_id: str | None = None,
    event_type: str | None = None,
    severity: str | None = None,
    limit: int = 10,
) -> list[SecurityEvent]:
    """
    Retrieve security events strictly within the authenticated user's scope.
    Controlled filters supported: resource_id, actor_id, event_type, severity, limit.
    """
    safe_limit = min(max(1, limit), 100)
    owned_ids = _get_owned_resource_ids(db, user)

    if resource_id:
        res = db.query(Resource).filter(Resource.id == resource_id).first()
        if not res:
            return []
        if res.owner_id == user.id:
            query = db.query(SecurityEvent).filter(SecurityEvent.resource_id == resource_id)
        else:
            query = db.query(SecurityEvent).filter(
                SecurityEvent.resource_id == resource_id,
                SecurityEvent.actor_id == user.id,
            )
    else:
        query = db.query(SecurityEvent).filter(
            or_(
                SecurityEvent.actor_id == user.id,
                SecurityEvent.resource_id.in_(owned_ids),
            )
        )

    if actor_id:
        if actor_id != user.id and (not resource_id or resource_id not in owned_ids):
            return []
        query = query.filter(SecurityEvent.actor_id == actor_id)

    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type)
    if severity:
        query = query.filter(SecurityEvent.severity == severity)

    return query.order_by(SecurityEvent.timestamp.desc()).limit(safe_limit).all()


def get_resource_activity(
    db: Session,
    user: User,
    resource_id: str,
    limit: int = 10,
) -> list[AuditEvent]:
    """
    Retrieve activity for a specific resource enforcing strict authorization:
    - Resource owners can see all activity for their resource.
    - Non-owners can only see their own interactions with that resource.
    """
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
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        return []

    is_authorized = False
    if incident.assigned_to_id == user.id or incident.reporter_id == user.id:
        is_authorized = True
    elif incident.resource_id:
        res = db.query(Resource).filter(Resource.id == incident.resource_id).first()
        if res and res.owner_id == user.id:
            is_authorized = True

    if not is_authorized:
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
        db.query(SecurityEvent)
        .join(IncidentEvent, IncidentEvent.security_event_id == SecurityEvent.id)
        .filter(IncidentEvent.incident_id == incident.id)
        .all()
    )

    owned_ids = _get_owned_resource_ids(db, user)
    processed_audit_ids: set[str] = set()

    for sec in linked_sec_events:
        if sec.actor_id == user.id or (sec.resource_id and sec.resource_id in owned_ids):
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
                audit = db.query(AuditEvent).filter(AuditEvent.id == sec.source_audit_id).first()
                if audit:
                    if audit.actor_id == user.id or (audit.resource_id and audit.resource_id in owned_ids):
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
    """Retrieve an incident if the user is assigned, reporter, or resource owner."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        return None

    if incident.assigned_to_id == user.id or incident.reporter_id == user.id:
        return incident

    if incident.resource_id:
        res = db.query(Resource).filter(Resource.id == incident.resource_id).first()
        if res and res.owner_id == user.id:
            return incident

    return None


def get_recent_incidents(db: Session, user: User, limit: int = 10) -> list[Incident]:
    """Retrieve recent incidents within caller authorization scope."""
    owned_ids = _get_owned_resource_ids(db, user)
    return (
        db.query(Incident)
        .filter(
            or_(
                Incident.assigned_to_id == user.id,
                Incident.reporter_id == user.id,
                Incident.resource_id.in_(owned_ids),
            )
        )
        .order_by(Incident.created_at.desc())
        .limit(limit)
        .all()
    )


def get_recent_security_events(db: Session, user: User, limit: int = 10) -> list[SecurityEvent]:
    """Retrieve security events where the user is actor or resource owner."""
    return get_security_events(db=db, user=user, limit=limit)


def get_recent_audit_events(db: Session, user: User, limit: int = 10) -> list[AuditEvent]:
    """Retrieve audit events where the user is actor or resource owner."""
    return get_audit_events(db=db, user=user, limit=limit)


def get_resource_security_activity(
    db: Session, user: User, resource_id: str, limit: int = 10
) -> list[AuditEvent]:
    """Retrieve security activity for a resource enforcing ownership or self-actor boundary."""
    return get_resource_activity(db=db, user=user, resource_id=resource_id, limit=limit)