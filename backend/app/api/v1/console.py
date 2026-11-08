from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.incident import Incident
from app.models.incident_event import IncidentEvent
from app.models.security_event import SecurityEvent
from app.models.user import User
from app.schemas.console import (
    AttachEventsRequest,
    DashboardSummaryRead,
    IncidentCreate,
    IncidentDetailRead,
    IncidentRead,
    IncidentUpdate,
)
from app.schemas.monitoring import SecurityEventRead
from app.services import administrative_access as admin

router = APIRouter()

ALLOWED_STATUS_PROGRESSION = {
    "OPEN": ["INVESTIGATING"],
    "INVESTIGATING": ["RESOLVED"],
    "RESOLVED": ["CLOSED"],
    "CLOSED": [],
}


@router.get("/incidents", response_model=list[IncidentRead])
def list_incidents(
    status_filter: str | None = Query(default=None, alias="status"),
    severity_filter: str | None = Query(default=None, alias="severity"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[IncidentRead]:
    query = admin.incident_query(db, current_user.id)
    if status_filter:
        query = query.filter(Incident.status == status_filter)
    if severity_filter:
        query = query.filter(Incident.severity == severity_filter)
    return query.order_by(Incident.created_at.desc()).all()


@router.post("/incidents", response_model=IncidentRead, status_code=status.HTTP_201_CREATED)
def create_incident(
    payload: IncidentCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> IncidentRead:
    actor_id = current_user.id
    with admin.mutation_transaction(db) as tx:
        admin.lock_resource_authority(tx, actor_id, payload.resource_id, admin.A.DEPARTMENT_INCIDENT_INVESTIGATE)
        events = admin.lock_events(tx, actor_id, payload.security_event_ids or [])
        admin.verify_assignee(tx, payload.assigned_to_id, payload.resource_id, events)
        incident = Incident(title=payload.title, description=payload.description, severity=payload.severity,
                            status="OPEN", reporter_id=actor_id, assigned_to_id=payload.assigned_to_id,
                            resource_id=payload.resource_id)
        tx.add(incident)
        tx.flush()
        for sec_id in dict.fromkeys(payload.security_event_ids or []):
            tx.add(IncidentEvent(incident_id=incident.id, security_event_id=sec_id))
        admin.append_audit(tx, actor_id=actor_id, resource_id=incident.resource_id,
                           action="INCIDENT_CREATED", reason="MANUAL_INCIDENT_CREATED",
                           context_data={"incident_id": incident.id, "severity": incident.severity})
        result = IncidentRead.model_validate(incident)
    return result


@router.get("/incidents/page")
def incident_page(
    status_filter: str | None = Query(default=None, alias="status"),
    severity: str | None = None, start: datetime | None = None, end: datetime | None = None,
    limit: int = Query(default=25, ge=1, le=100), offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db),
):
    from sqlalchemy import select, func
    from app.models import RiskAssessment
    from app.services.risk_monitoring import monitoring_query
    from app.services.security_console import visible_incidents, validate_window, window
    monitoring_query(db, current_user.id, RiskAssessment)
    validate_window(start, end)
    query = select(Incident).where(Incident.id.in_(visible_incidents(db, current_user.id)))
    if status_filter:
        query = query.where(Incident.status == status_filter)
    if severity:
        query = query.where(Incident.severity == severity)
    query = window(query, Incident.created_at, start, end)
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    rows = db.scalars(query.order_by(Incident.created_at.desc(), Incident.id.desc()).limit(limit).offset(offset)).all()
    return {"items": [IncidentRead.model_validate(row).model_dump(mode="json") for row in rows],
            "total": total, "limit": limit, "offset": offset}


@router.get("/incidents/{incident_id}", response_model=IncidentDetailRead)
def get_incident_detail(
    incident_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> IncidentDetailRead:
    incident = admin.incident_query(db, current_user.id).filter(Incident.id == incident_id).first()
    if incident is None:
        raise HTTPException(404, "Incident not found or access unauthorized")
    detail = IncidentDetailRead.model_validate(incident)
    detail.security_events = [SecurityEventRead.model_validate(event) for event in
        admin.security_query(db, current_user.id).join(
            IncidentEvent, IncidentEvent.security_event_id == SecurityEvent.id
        ).filter(IncidentEvent.incident_id == incident_id).all()]
    from app.models import AuditEvent
    from app.schemas.risk import DetectionRead
    detail.detection_evidence = [DetectionRead.model_validate(event).model_dump(mode="json") for event in
        admin.security_query(db, current_user.id).join(IncidentEvent, IncidentEvent.security_event_id == SecurityEvent.id)
        .filter(IncidentEvent.incident_id == incident_id).all()]
    detail.history = [{"id": row.id, "timestamp": row.timestamp, "actor_id": row.actor_id,
                       "action": row.action, "status": (row.context_data or {}).get("status")}
        for row in admin.audit_query(db, current_user.id).filter(
            AuditEvent.context_data["incident_id"].as_string() == incident_id,
            AuditEvent.action.in_(["INCIDENT_CREATED", "INCIDENT_UPDATED", "INCIDENT_EVENTS_ATTACHED"]))
        .order_by(AuditEvent.timestamp.desc(), AuditEvent.id.desc()).all()]
    return detail


@router.patch("/incidents/{incident_id}", response_model=IncidentRead)
def update_incident(
    incident_id: str,
    payload: IncidentUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> IncidentRead:
    actor_id = current_user.id
    with admin.mutation_transaction(db) as tx:
        incident = admin.lock_incident(tx, actor_id, incident_id)
        events = tx.query(SecurityEvent).join(IncidentEvent).filter(IncidentEvent.incident_id == incident.id).all()
        if payload.assigned_to_id is not None:
            admin.verify_assignee(tx, payload.assigned_to_id, incident.resource_id, events)
        if payload.status and payload.status != incident.status:
            if payload.status not in ALLOWED_STATUS_PROGRESSION.get(incident.status, []):
                raise HTTPException(400, f"Invalid status transition from '{incident.status}' to '{payload.status}'")
            if payload.status == "RESOLVED":
                if not (payload.resolution_notes or incident.resolution_notes):
                    raise HTTPException(400, "resolution_notes are required when resolving an incident")
                incident.resolved_at = datetime.now(timezone.utc)
            incident.status = payload.status
        if payload.assigned_to_id is not None:
            incident.assigned_to_id = payload.assigned_to_id
        if payload.resolution_notes is not None:
            incident.resolution_notes = payload.resolution_notes
        incident.updated_at = datetime.now(timezone.utc)
        admin.append_audit(tx, actor_id=actor_id, resource_id=incident.resource_id,
                           action="INCIDENT_UPDATED", reason="INCIDENT_STATUS_UPDATED",
                           context_data={"incident_id": incident.id, "status": incident.status})
        result = IncidentRead.model_validate(incident)
    return result


@router.post("/incidents/{incident_id}/events", response_model=IncidentDetailRead)
def attach_security_events_to_incident(
    incident_id: str,
    payload: AttachEventsRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> IncidentDetailRead:
    actor_id = current_user.id
    with admin.mutation_transaction(db) as tx:
        incident = admin.lock_incident(tx, actor_id, incident_id)
        events = admin.lock_events(tx, actor_id, payload.security_event_ids)
        # A legacy assignee is provenance, not authority. New assignments are
        # validated on create/update; attaching evidence grants it no access.
        for sec_id in dict.fromkeys(payload.security_event_ids):
            if not tx.query(IncidentEvent).filter_by(incident_id=incident.id, security_event_id=sec_id).first():
                tx.add(IncidentEvent(incident_id=incident.id, security_event_id=sec_id))
        admin.append_audit(tx, actor_id=actor_id, resource_id=incident.resource_id,
                           action="INCIDENT_EVENTS_ATTACHED", reason="INCIDENT_EVIDENCE_ATTACHED",
                           context_data={"incident_id": incident.id, "attached_event_count": len(events)})
        result = get_incident_detail(incident_id, current_user, tx)
    return result


@router.get("/dashboard/summary", response_model=DashboardSummaryRead)
def get_dashboard_summary(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DashboardSummaryRead:
    return DashboardSummaryRead(
        total_open_incidents=admin.incident_query(db, current_user.id).filter(
            Incident.status.in_(["OPEN", "INVESTIGATING"])).count(),
        critical_security_events=admin.security_query(db, current_user.id).filter(
            SecurityEvent.severity == "CRITICAL").count(),
        pending_access_requests=admin.pending_query(db, current_user.id).count(),
    )


@router.get("/dashboard/security-overview")
def security_overview(
    start: datetime | None = None, end: datetime | None = None,
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db),
):
    from app.services.security_console import overview
    return overview(db, current_user.id, start=start, end=end)
