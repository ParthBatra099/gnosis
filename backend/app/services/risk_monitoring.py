"""Read-only monitoring queries; scope before filters, totals and pagination."""
from fastapi import HTTPException
from sqlalchemy import func, select
from app.models import RiskAssessment, SecurityEvent
from app.services import administrative_access as admin
from app.services.risk_service import utc


def monitoring_query(db, actor_id, model):
    global_access = admin.global_monitor(db, actor_id)
    if not global_access and not admin.departments(db, actor_id, admin.A.DEPARTMENT_SECURITY_MONITOR):
        raise HTTPException(403, "Security monitoring not authorized")
    if model is SecurityEvent:
        return select(model).where(admin.security_predicate(db, actor_id))
    query = select(model)
    if not global_access:
        query = query.where(admin.complete_monitoring_scope(db, actor_id, model.id, "assessment_id"))
    return query


def page(db, actor_id, model, schema, *, employee_id=None, scope=None, scope_key=None,
         start=None, end=None, limit=25, offset=0, severity=None, event_type=None, incident_status=None):
    query = monitoring_query(db, actor_id, model)
    for value in (start, end):
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise HTTPException(422, "Time bounds require a timezone")
    if start and end and start >= end:
        raise HTTPException(422, "start must precede end")
    if employee_id:
        query = query.where(model.actor_id == employee_id)
    if scope:
        query = query.where(model.scope == scope)
    if scope_key:
        query = query.where(model.scope_key == scope_key)
    if model is SecurityEvent:
        if severity:
            query = query.where(model.severity == severity)
        if event_type:
            query = query.where(model.event_type == event_type)
        if incident_status:
            from app.models import Incident, IncidentEvent
            from app.services.security_console import visible_incidents
            query = query.where(model.id.in_(select(IncidentEvent.security_event_id).join(
                Incident, Incident.id == IncidentEvent.incident_id).where(
                Incident.id.in_(visible_incidents(db, actor_id)), Incident.status == incident_status)))
    if start:
        query = query.where(model.timestamp >= utc(start))
    if end:
        query = query.where(model.timestamp < utc(end))
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    rows = db.scalars(query.order_by(model.timestamp.desc(), model.id.desc()).limit(limit).offset(offset)).all()
    items = [schema.model_validate(row).model_dump(mode="json") for row in rows]
    if model is SecurityEvent:
        from app.services.security_console import incident_references
        references = incident_references(db, actor_id, [row.id for row in rows])
        for item in items:
            item["related_incidents"] = references.get(item["id"], [])
    return {"total": total, "limit": limit, "offset": offset, "items": items}
