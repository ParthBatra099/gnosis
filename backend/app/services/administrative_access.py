"""Administrative integration only. Never grants business-data access or MFA assurance."""

from contextlib import contextmanager
import logging

from fastapi import HTTPException
from sqlalchemy import and_, exists, or_, select, true
from sqlalchemy.orm import Session, aliased

from app.models import AccessRequest, Department, Resource
from app.models.audit_event import AuditEvent
from app.models.incident import Incident
from app.models.incident_event import IncidentEvent
from app.models.security_event import SecurityEvent
from app.models.risk_assessment import MonitoringScope
from app.security.detection_engine import evaluate_detection_rules
from app.services import organization_authority as authority

A = authority.AdministrativeAction


def require(decision):
    if not decision.allowed:
        code = 404 if decision.reason is authority.AuthorityReason.SCOPE_NOT_FOUND else 403
        raise HTTPException(code, detail=decision.reason.value)
    return decision


@contextmanager
def mutation_transaction(source: Session):
    """Explicit caller transaction on the existing bind; never discard auth's work.

    Authentication has already resolved the actor with get_current_user and may
    have autobegun its read session. A normal SQLAlchemy Session on that same bind
    owns this operation, its locks and strict audit write. No second engine/config.
    Responses must be materialized before closing this session.
    """
    with Session(bind=source.get_bind(), autoflush=False, expire_on_commit=False) as db:
        with db.begin():
            yield db
        # Detection never owns commits. Keep observation after the atomic mutation.
        for event in db.info.get("administrative_audits", []):
            try:
                with db.begin():
                    evaluate_detection_rules(db, event)
            except Exception:
                db.rollback()
                logging.getLogger(__name__).error("Post-commit detection failed")


def append_audit(db, *, actor_id, resource_id, action, reason, context_data):
    event = AuditEvent(actor_id=actor_id, resource_id=resource_id, action=action,
                       outcome="ALLOW", reason=reason, context_data=context_data)
    db.add(event)
    db.flush()  # Failure propagates and rolls back the mutation as well.
    db.info.setdefault("administrative_audits", []).append(event)


def departments(db, actor_id, action):
    """All role/assignment decisions belong to Unit 3, including global users."""
    return tuple(department_id for department_id in db.scalars(select(Department.id))
                 if authority.evaluate_authority(
                     db, actor_id, action, authority.DepartmentScope(department_id)).allowed)


def resource_predicate(db, actor_id, action, column):
    ids = departments(db, actor_id, action)
    # Make this two-valued even for unscoped records. NOT EXISTS evidence checks
    # must treat NULL resource scope as denied, never SQL UNKNOWN.
    return and_(column.is_not(None), column.in_(
        select(Resource.id).where(Resource.department_id.in_(ids))))


def global_monitor(db, actor_id):
    return authority.evaluate_authority(
        db, actor_id, A.ORGANIZATION_SECURITY_MONITOR, authority.OrganizationScope()).allowed


def audit_predicate(db, actor_id, model=AuditEvent):
    if global_monitor(db, actor_id):
        return true()
    incident_action = model.action.like("INCIDENT_%")
    incident_id = model.context_data["incident_id"].as_string()
    visible_incident = exists(select(Incident.id).where(Incident.id == incident_id,
                                                       incident_predicate(db, actor_id)))
    return and_(resource_predicate(db, actor_id, A.DEPARTMENT_SECURITY_MONITOR, model.resource_id),
                or_(~incident_action, visible_incident))


def security_predicate(db, actor_id, model=SecurityEvent, action=A.DEPARTMENT_SECURITY_MONITOR):
    if global_monitor(db, actor_id):
        return true()
    source = aliased(AuditEvent)
    return and_(
        resource_predicate(db, actor_id, action, model.resource_id),
        or_(model.source_audit_id.is_(None), exists(select(source.id).where(
            source.id == model.source_audit_id,
            resource_predicate(db, actor_id, action, source.resource_id)))),
        or_(model.evidence.is_(None), complete_monitoring_scope(db, actor_id, model.id, "security_event_id", action)),
    )


def complete_monitoring_scope(db, actor_id, target_id, target_column, action=A.DEPARTMENT_SECURITY_MONITOR):
    """Every evidence department must be authorized. Unknown/missing scope fails closed."""
    ids = departments(db, actor_id, action)
    column = getattr(MonitoringScope, target_column)
    present = exists(select(MonitoringScope.id).where(column == target_id))
    forbidden = exists(select(MonitoringScope.id).where(column == target_id,
        or_(MonitoringScope.department_id.is_(None), ~MonitoringScope.department_id.in_(ids))))
    return and_(present, ~forbidden)


def incident_predicate(db, actor_id):
    if global_monitor(db, actor_id):
        return true()
    event = aliased(SecurityEvent)
    forbidden_link = exists(select(IncidentEvent.id).outerjoin(
        event, event.id == IncidentEvent.security_event_id).where(
            IncidentEvent.incident_id == Incident.id,
            or_(event.id.is_(None), ~security_predicate(
                db, actor_id, event, A.DEPARTMENT_INCIDENT_INVESTIGATE))))
    return and_(resource_predicate(db, actor_id, A.DEPARTMENT_INCIDENT_INVESTIGATE,
                                   Incident.resource_id), ~forbidden_link)


def audit_query(db, actor_id):
    return db.query(AuditEvent).filter(audit_predicate(db, actor_id))


def security_query(db, actor_id):
    return db.query(SecurityEvent).filter(security_predicate(db, actor_id))


def incident_query(db, actor_id):
    return db.query(Incident).filter(incident_predicate(db, actor_id))


def pending_query(db, actor_id):
    return db.query(AccessRequest).filter(
        AccessRequest.status == "PENDING",
        resource_predicate(db, actor_id, A.DEPARTMENT_GRANT_ADMINISTER, AccessRequest.resource_id))


def lock_resource_authority(db, actor_id, resource_id, action):
    """Identity first, target row lock, then fresh scope decision under both locks."""
    if resource_id is None:
        return require(authority.revalidate_authority_for_mutation(
            db, actor_id, A.ORGANIZATION_ADMINISTER, authority.OrganizationScope()))
    department_id = db.scalar(select(Resource.department_id).where(Resource.id == resource_id))
    if department_id is None:
        raise HTTPException(404, "Resource not found")
    require(authority.revalidate_authority_for_mutation(
        db, actor_id, action, authority.DepartmentScope(department_id)))
    department_id = db.scalar(select(Resource.department_id).where(
        Resource.id == resource_id).with_for_update())
    return require(authority.revalidate_authority_for_mutation(
        db, actor_id, action, authority.DepartmentScope(department_id)))


def lock_events(db, actor_id, event_ids):
    events = []
    for event_id in sorted(set(event_ids)):
        event = db.query(SecurityEvent).filter_by(id=event_id).with_for_update().populate_existing().first()
        if event is None:
            raise HTTPException(404, "SecurityEvent not found")
        lock_resource_authority(db, actor_id, event.resource_id, A.DEPARTMENT_INCIDENT_INVESTIGATE)
        if event.source_audit_id:
            audit = db.query(AuditEvent).filter_by(id=event.source_audit_id).with_for_update().first()
            if audit is None:
                raise HTTPException(403, "Unresolved evidence scope")
            lock_resource_authority(db, actor_id, audit.resource_id, A.DEPARTMENT_INCIDENT_INVESTIGATE)
        events.append(event)
    return events


def lock_incident(db, actor_id, incident_id):
    incident = incident_query(db, actor_id).filter(Incident.id == incident_id).first()
    if incident is None:
        raise HTTPException(404, "Incident not found or access unauthorized")
    lock_resource_authority(db, actor_id, incident.resource_id, A.DEPARTMENT_INCIDENT_INVESTIGATE)
    incident = db.query(Incident).filter_by(id=incident_id).with_for_update().populate_existing().one()
    lock_resource_authority(db, actor_id, incident.resource_id, A.DEPARTMENT_INCIDENT_INVESTIGATE)
    event_ids = db.scalars(select(IncidentEvent.security_event_id).where(
        IncidentEvent.incident_id == incident.id)).all()
    lock_events(db, actor_id, event_ids)
    return incident


def verify_assignee(db, assignee_id, resource_id, events):
    if assignee_id is None:
        return
    # Eligibility is current investigative authority, never assignee status itself.
    lock_resource_authority(db, assignee_id, resource_id, A.DEPARTMENT_INCIDENT_INVESTIGATE)
    lock_events(db, assignee_id, [event.id for event in events])
