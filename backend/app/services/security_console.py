"""Scoped read projections over existing evidence. No new event storage."""
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy import String, case, func, literal, select, union_all

from app.models import AuditEvent, DataDisclosure, Incident, IncidentEvent, MonitoringScope, Resource, RiskAssessment, SecurityEvent
from app.schemas.risk import DetectionRead, RiskRead
from app.services import administrative_access as admin
from app.services.exposure_service import scoped_disclosures
from app.services.risk_monitoring import monitoring_query
from app.services.risk_service import utc


def validate_window(start, end):
    for value in (start, end):
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise HTTPException(422, "Time bounds require a timezone")
    if start and end and start >= end:
        raise HTTPException(422, "start must precede end")


def window(query, column, start, end):
    if start:
        query = query.where(column >= utc(start))
    if end:
        query = query.where(column < utc(end))
    return query


def visible_incidents(db, actor_id):
    return select(Incident.id).where(admin.incident_predicate(db, actor_id))


def incident_references(db, actor_id, event_ids):
    if not event_ids:
        return {}
    rows = db.execute(select(IncidentEvent.security_event_id, Incident.id, Incident.status).join(
        Incident, Incident.id == IncidentEvent.incident_id).where(
        IncidentEvent.security_event_id.in_(event_ids), Incident.id.in_(visible_incidents(db, actor_id))))
    result = {}
    for event_id, incident_id, status in rows:
        result.setdefault(event_id, []).append({"id": incident_id, "status": status})
    return result


def timeline_query(db, actor_id):
    # Also enforces canonical administrative monitoring authority for empty scopes.
    monitoring_query(db, actor_id, RiskAssessment)
    incident_ids = visible_incidents(db, actor_id)
    null = literal(None, type_=String())
    def projection(query, model, source, *, actor, category, resource=null, department=null,
                   severity=null, outcome=null, explanation=null, session=null,
                   record=null, sensitivity=null, incident=null, timestamp=None):
        return query.with_only_columns(
            literal(source).label("source"), model.id.label("source_id"),
            (timestamp if timestamp is not None else model.timestamp).label("timestamp"),
            actor.label("actor_id"), category.label("category"), resource.label("resource_id"),
            department.label("department_id"), severity.label("severity"), outcome.label("outcome"),
            explanation.label("explanation"), session.label("session_ref"), record.label("record_id"),
            sensitivity.label("sensitivity"), incident.label("incident_id"), maintain_column_froms=True)

    incident_action = AuditEvent.action.like("INCIDENT_%")
    incident_ref = AuditEvent.context_data["incident_id"].as_string()
    audits = select(AuditEvent).where(admin.audit_predicate(db, actor_id),
        AuditEvent.action != "INCIDENT_CREATED",
        ~incident_action | incident_ref.in_(incident_ids))
    audit_category = case((AuditEvent.action == "RESOURCE_ACCESS", case(
        (AuditEvent.outcome == "DENY", literal("ACCESS_DENIED")), else_=literal("ACCESS_ALLOWED"))),
        (incident_action, literal("INCIDENT_UPDATED")), else_=literal("AUDIT_EVENT"))
    audit_rows = projection(audits, AuditEvent, "audit", actor=AuditEvent.actor_id,
        category=audit_category, resource=AuditEvent.resource_id,
        department=AuditEvent.context_data["department_id"].as_string(),
        outcome=AuditEvent.outcome, explanation=AuditEvent.action,
        session=AuditEvent.context_data["session_ref"].as_string(),
        incident=case((incident_action, incident_ref), else_=null))
    disclosure_rows = projection(scoped_disclosures(db, actor_id), DataDisclosure, "disclosure",
        actor=DataDisclosure.actor_id, category=literal("DATA_DISCLOSED"), resource=DataDisclosure.resource_id,
        department=DataDisclosure.department_id, record=DataDisclosure.record_id,
        sensitivity=DataDisclosure.sensitivity, session=DataDisclosure.session_ref,
        outcome=DataDisclosure.completion_state,
        explanation=literal("Application prepared this business record; network delivery UNKNOWN."))
    detection_rows = projection(monitoring_query(db, actor_id, SecurityEvent), SecurityEvent, "detection",
        actor=SecurityEvent.actor_id, category=literal("SECURITY_DETECTION"), resource=SecurityEvent.resource_id,
        severity=SecurityEvent.severity, explanation=SecurityEvent.description,
        session=SecurityEvent.evidence["session_ref"].as_string())
    risk_rows = projection(monitoring_query(db, actor_id, RiskAssessment), RiskAssessment, "risk",
        actor=RiskAssessment.actor_id, category=literal("RISK_ASSESSMENT"), severity=RiskAssessment.level,
        explanation=literal("Recorded observational risk assessment; not a probability or access decision."),
        session=case((RiskAssessment.scope == "SESSION", RiskAssessment.scope_key), else_=null))
    incident_query = select(Incident).where(Incident.id.in_(incident_ids))
    incident_rows = projection(incident_query, Incident, "incident", actor=Incident.reporter_id,
        category=literal("INCIDENT_CREATED"), resource=Incident.resource_id, severity=Incident.severity,
        outcome=literal("CREATED"), explanation=literal("Incident created; current status is available in incident details."),
        incident=Incident.id, timestamp=Incident.created_at)
    return union_all(audit_rows, disclosure_rows, detection_rows, risk_rows, incident_rows).subquery()


def timeline(db, actor_id, *, employee_id=None, session_ref=None, category=None, severity=None,
             start=None, end=None, limit=25, offset=0):
    validate_window(start, end)
    rows = timeline_query(db, actor_id)
    query = select(rows)
    if employee_id:
        associated = select(Incident.id).where(Incident.id.in_(visible_incidents(db, actor_id)),
            (Incident.reporter_id == employee_id) | Incident.id.in_(select(IncidentEvent.incident_id).join(
                SecurityEvent, SecurityEvent.id == IncidentEvent.security_event_id).where(SecurityEvent.actor_id == employee_id)))
        query = query.where((rows.c.actor_id == employee_id) | rows.c.incident_id.in_(associated))
    for column, value in ((rows.c.session_ref, session_ref),
                          (rows.c.category, category), (rows.c.severity, severity)):
        if value:
            query = query.where(column == value)
    query = window(query, rows.c.timestamp, start, end)
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    results = [dict(r._mapping) for r in db.execute(query.order_by(
        rows.c.timestamp.desc(), rows.c.source, rows.c.source_id.desc()).limit(limit).offset(offset))]
    references = incident_references(db, actor_id, [r["source_id"] for r in results if r["source"] == "detection"])
    for item in results:
        item["id"] = item["source"] + ":" + item["source_id"]
        item["timestamp"] = utc(item["timestamp"])
        item["related_incidents"] = references.get(item["source_id"], []) if item["source"] == "detection" else []
        item["transport_state"] = "UNKNOWN" if item["source"] == "disclosure" else None
        item["status"] = None
        item["details"] = None
        if item["source"] == "risk":
            item["details"] = RiskRead.model_validate(db.get(RiskAssessment, item["source_id"])).model_dump(mode="json")
        elif item["source"] == "detection":
            item["details"] = DetectionRead.model_validate(db.get(SecurityEvent, item["source_id"])).model_dump(mode="json")
        if item["source"] == "audit" and item["category"] == "INCIDENT_UPDATED":
            status = (db.get(AuditEvent, item["source_id"]).context_data or {}).get("status")
            item["status"] = status if status in {"OPEN", "INVESTIGATING", "RESOLVED", "CLOSED"} else None
        ref = item["session_ref"]
        if ref and (len(ref) != 64 or any(c not in "0123456789abcdef" for c in ref)):
            item["session_ref"] = None
        item["department_ids"] = [item["department_id"]] if item["department_id"] else []
        if item["source"] in {"risk", "detection"}:
            column = MonitoringScope.assessment_id if item["source"] == "risk" else MonitoringScope.security_event_id
            item["department_ids"] = list(db.scalars(select(MonitoringScope.department_id).where(
                column == item["source_id"], MonitoringScope.department_id.is_not(None))))
    return {"total": total, "limit": limit, "offset": offset, "items": results}


def overview(db, actor_id, start=None, end=None):
    end = end or datetime.now(timezone.utc)
    start = start or end - timedelta(days=7)
    validate_window(start, end)
    detections = window(monitoring_query(db, actor_id, SecurityEvent), SecurityEvent.timestamp, start, end)
    risks = window(monitoring_query(db, actor_id, RiskAssessment), RiskAssessment.timestamp, start, end)
    exposures = window(scoped_disclosures(db, actor_id), DataDisclosure.timestamp, start, end)
    def count(query):
        return db.scalar(select(func.count()).select_from(query.subquery()))
    # Rank only visible, in-period employee assessments, then count elevated latests.
    latest = risks.where(RiskAssessment.scope == "EMPLOYEE").add_columns(
        func.row_number().over(partition_by=RiskAssessment.actor_id,
            order_by=(RiskAssessment.timestamp.desc(), RiskAssessment.id.desc())).label("position")).subquery()
    elevated = db.scalar(select(func.count()).select_from(latest).where(
        latest.c.position == 1, latest.c.level.in_(["HIGH", "CRITICAL"])))
    incidents = select(Incident).where(Incident.id.in_(visible_incidents(db, actor_id)))
    event_rows = db.scalars(detections.order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc()).limit(5)).all()
    risk_rows = db.scalars(select(RiskAssessment).join(latest, latest.c.id == RiskAssessment.id)
        .where(latest.c.position == 1).order_by(RiskAssessment.score.desc(), RiskAssessment.timestamp.desc()).limit(5)).all()
    return {"start": start, "end": end,
        "detections": count(detections),
        "high_detections": count(detections.where(SecurityEvent.severity == "HIGH")),
        "critical_detections": count(detections.where(SecurityEvent.severity == "CRITICAL")),
        "elevated_employees": elevated,
        "open_incidents": count(incidents.where(Incident.status == "OPEN")),
        "investigating_incidents": count(incidents.where(Incident.status == "INVESTIGATING")),
        "resolved_incidents": count(incidents.where(Incident.status == "RESOLVED")),
        "closed_incidents": count(incidents.where(Incident.status == "CLOSED")),
        "disclosure_events": count(exposures),
        "distinct_records": db.scalar(select(func.count(func.distinct(exposures.subquery().c.record_id)))),
        "recent_detections": [DetectionRead.model_validate(r).model_dump(mode="json") for r in event_rows],
        "employee_risks": [RiskRead.model_validate(r).model_dump(mode="json") for r in risk_rows],
        "recent_activity": timeline(db, actor_id, start=start, end=end, limit=5)["items"]}
