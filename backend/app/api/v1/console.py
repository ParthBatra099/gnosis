from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.access_request import AccessRequest
from app.models.incident import Incident
from app.models.incident_event import IncidentEvent
from app.models.resource import Resource
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
from app.services.audit_service import record_audit_event

router = APIRouter()

ALLOWED_STATUS_PROGRESSION = {
    "OPEN": ["INVESTIGATING"],
    "INVESTIGATING": ["RESOLVED"],
    "RESOLVED": ["CLOSED"],
    "CLOSED": [],
}


def _verify_incident_access(incident: Incident, current_user: User, db: Session) -> bool:
    """Server-side check verifying caller is resource owner, assignee, or reporter."""
    if incident.assigned_to_id == current_user.id or incident.reporter_id == current_user.id:
        return True
    if incident.resource_id:
        res = db.query(Resource).filter(Resource.id == incident.resource_id).first()
        if res and res.owner_id == current_user.id:
            return True
    return False


def _verify_security_event_access(sec_event: SecurityEvent, current_user: User, db: Session) -> bool:
    """Server-side check verifying caller is authorized for the security event."""
    if sec_event.actor_id == current_user.id:
        return True
    if sec_event.resource_id:
        res = db.query(Resource).filter(Resource.id == sec_event.resource_id).first()
        if res and res.owner_id == current_user.id:
            return True
    return False


def _verify_assignee(assignee_id: str | None, db: Session) -> None:
    """Validates that assigned_to_id belongs to an active user."""
    if assignee_id is not None:
        user = db.query(User).filter(User.id == assignee_id).first()
        if not user or not user.active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Assigned user does not exist or is inactive",
            )


@router.get("/incidents", response_model=list[IncidentRead])
def list_incidents(
    status_filter: str | None = Query(default=None, alias="status"),
    severity_filter: str | None = Query(default=None, alias="severity"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[IncidentRead]:
    """List incidents within caller's authorized scope."""
    owned_resource_ids = [
        r.id for r in db.query(Resource.id).filter(Resource.owner_id == current_user.id).all()
    ]

    query = db.query(Incident).filter(
        or_(
            Incident.assigned_to_id == current_user.id,
            Incident.reporter_id == current_user.id,
            Incident.resource_id.in_(owned_resource_ids),
        )
    )

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
    """Manually create an incident for an owned resource."""
    if payload.resource_id:
        res = db.query(Resource).filter(Resource.id == payload.resource_id).first()
        if not res or res.owner_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only the resource owner can create incidents for this resource",
            )

    _verify_assignee(payload.assigned_to_id, db)

    incident = Incident(
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        status="OPEN",
        reporter_id=current_user.id,
        assigned_to_id=payload.assigned_to_id,
        resource_id=payload.resource_id,
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)

    # Attach optionally supplied security events
    if payload.security_event_ids:
        for sec_id in payload.security_event_ids:
            sec_event = db.query(SecurityEvent).filter(SecurityEvent.id == sec_id).first()
            if not sec_event:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"SecurityEvent '{sec_id}' not found",
                )
            if not _verify_security_event_access(sec_event, current_user, db):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Unauthorized to attach SecurityEvent '{sec_id}'",
                )

            link_exists = (
                db.query(IncidentEvent)
                .filter(
                    IncidentEvent.incident_id == incident.id,
                    IncidentEvent.security_event_id == sec_id,
                )
                .first()
            )
            if not link_exists:
                db.add(IncidentEvent(incident_id=incident.id, security_event_id=sec_id))
        db.commit()
        db.refresh(incident)

    record_audit_event(
        db=db,
        action="INCIDENT_CREATED",
        outcome="ALLOW",
        actor_id=current_user.id,
        resource_id=payload.resource_id,
        reason="MANUAL_INCIDENT_CREATED",
        context_data={"incident_id": incident.id, "severity": payload.severity},
    )

    return incident


@router.get("/incidents/{incident_id}", response_model=IncidentDetailRead)
def get_incident_detail(
    incident_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> IncidentDetailRead:
    """Retrieve detailed incident record along with linked security events."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident or not _verify_incident_access(incident, current_user, db):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found or access unauthorized",
        )

    linked_events = (
        db.query(SecurityEvent)
        .join(IncidentEvent, IncidentEvent.security_event_id == SecurityEvent.id)
        .filter(IncidentEvent.incident_id == incident.id)
        .all()
    )

    detail = IncidentDetailRead.model_validate(incident)
    detail.security_events = [SecurityEventRead.model_validate(e) for e in linked_events]
    return detail


@router.patch("/incidents/{incident_id}", response_model=IncidentRead)
def update_incident(
    incident_id: str,
    payload: IncidentUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> IncidentRead:
    """Update incident status, assignee, or resolution notes enforcing status progression."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident or not _verify_incident_access(incident, current_user, db):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found or access unauthorized",
        )

    if payload.assigned_to_id is not None:
        _verify_assignee(payload.assigned_to_id, db)
        incident.assigned_to_id = payload.assigned_to_id

    if payload.status and payload.status != incident.status:
        allowed = ALLOWED_STATUS_PROGRESSION.get(incident.status, [])
        if payload.status not in allowed:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status transition from '{incident.status}' to '{payload.status}'",
            )
        if payload.status == "RESOLVED":
            notes = payload.resolution_notes or incident.resolution_notes
            if not notes:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="resolution_notes are required when resolving an incident",
                )
            incident.resolved_at = datetime.now(timezone.utc)
        incident.status = payload.status

    if payload.resolution_notes is not None:
        incident.resolution_notes = payload.resolution_notes

    incident.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(incident)

    record_audit_event(
        db=db,
        action="INCIDENT_UPDATED",
        outcome="ALLOW",
        actor_id=current_user.id,
        resource_id=incident.resource_id,
        reason="INCIDENT_STATUS_UPDATED",
        context_data={"incident_id": incident.id, "status": incident.status},
    )

    return incident


@router.post("/incidents/{incident_id}/events", response_model=IncidentDetailRead)
def attach_security_events_to_incident(
    incident_id: str,
    payload: AttachEventsRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> IncidentDetailRead:
    """Attach security events to an existing incident avoiding duplicate linkages."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident or not _verify_incident_access(incident, current_user, db):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found or access unauthorized",
        )

    for sec_id in payload.security_event_ids:
        sec_event = db.query(SecurityEvent).filter(SecurityEvent.id == sec_id).first()
        if not sec_event:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"SecurityEvent '{sec_id}' not found",
            )
        if not _verify_security_event_access(sec_event, current_user, db):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Unauthorized to attach SecurityEvent '{sec_id}'",
            )

        link_exists = (
            db.query(IncidentEvent)
            .filter(
                IncidentEvent.incident_id == incident.id,
                IncidentEvent.security_event_id == sec_id,
            )
            .first()
        )
        if not link_exists:
            db.add(IncidentEvent(incident_id=incident.id, security_event_id=sec_id))

    db.commit()
    return get_incident_detail(incident_id, current_user, db)


@router.get("/dashboard/summary", response_model=DashboardSummaryRead)
def get_dashboard_summary(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DashboardSummaryRead:
    """Return dashboard summary metrics within the caller's authorized scope."""
    owned_resource_ids = [
        r.id for r in db.query(Resource.id).filter(Resource.owner_id == current_user.id).all()
    ]

    total_open = (
        db.query(Incident)
        .filter(
            Incident.status.in_(["OPEN", "INVESTIGATING"]),
            or_(
                Incident.assigned_to_id == current_user.id,
                Incident.reporter_id == current_user.id,
                Incident.resource_id.in_(owned_resource_ids),
            ),
        )
        .count()
    )

    critical_events = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.severity == "CRITICAL",
            or_(
                SecurityEvent.actor_id == current_user.id,
                SecurityEvent.resource_id.in_(owned_resource_ids),
            ),
        )
        .count()
    )

    pending_requests = (
        db.query(AccessRequest)
        .join(Resource, AccessRequest.resource_id == Resource.id)
        .filter(
            Resource.owner_id == current_user.id,
            AccessRequest.status == "PENDING",
        )
        .count()
    )

    return DashboardSummaryRead(
        total_open_incidents=total_open,
        critical_security_events=critical_events,
        pending_access_requests=pending_requests,
    )