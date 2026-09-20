from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.models.audit_event import AuditEvent
from app.models.incident import Incident
from app.models.resource import Resource
from app.models.security_event import SecurityEvent
from app.models.user import User


def _get_owned_resource_ids(db: Session, user: User) -> list[str]:
    """Helper to fetch resource IDs owned by the authenticated user."""
    return [r.id for r in db.query(Resource.id).filter(Resource.owner_id == user.id).all()]


def get_recent_security_events(db: Session, user: User, limit: int = 10) -> list[SecurityEvent]:
    """Retrieve security events where the user is actor or resource owner."""
    owned_ids = _get_owned_resource_ids(db, user)
    return (
        db.query(SecurityEvent)
        .filter(
            or_(
                SecurityEvent.actor_id == user.id,
                SecurityEvent.resource_id.in_(owned_ids),
            )
        )
        .order_by(SecurityEvent.timestamp.desc())
        .limit(limit)
        .all()
    )


def get_recent_audit_events(db: Session, user: User, limit: int = 10) -> list[AuditEvent]:
    """Retrieve audit events where the user is actor or resource owner."""
    owned_ids = _get_owned_resource_ids(db, user)
    return (
        db.query(AuditEvent)
        .filter(
            or_(
                AuditEvent.actor_id == user.id,
                AuditEvent.resource_id.in_(owned_ids),
            )
        )
        .order_by(AuditEvent.timestamp.desc())
        .limit(limit)
        .all()
    )


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


def get_resource_security_activity(
    db: Session, user: User, resource_id: str, limit: int = 10
) -> list[AuditEvent]:
    """Retrieve security activity for a resource enforcing ownership or self-actor boundary."""
    res = db.query(Resource).filter(Resource.id == resource_id).first()
    if not res:
        return []

    if res.owner_id == user.id:
        return (
            db.query(AuditEvent)
            .filter(AuditEvent.resource_id == resource_id)
            .order_by(AuditEvent.timestamp.desc())
            .limit(limit)
            .all()
        )

    return (
        db.query(AuditEvent)
        .filter(AuditEvent.resource_id == resource_id, AuditEvent.actor_id == user.id)
        .order_by(AuditEvent.timestamp.desc())
        .limit(limit)
        .all()
    )