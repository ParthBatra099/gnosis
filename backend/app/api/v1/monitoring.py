from fastapi import APIRouter, Depends, Query
from datetime import datetime
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.audit_event import AuditEvent
from app.models.security_event import SecurityEvent
from app.models.user import User
from app.schemas.monitoring import AuditEventRead, SecurityEventRead
from app.services import administrative_access as admin

router = APIRouter()


@router.get("/detections")
def detections(
    employee_id: str | None = None, start: datetime | None = None, end: datetime | None = None,
    limit: int = Query(default=25, ge=1, le=100), offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db),
    severity: str | None = None, event_type: str | None = None, incident_status: str | None = None,
):
    from app.schemas.risk import DetectionRead
    from app.services.risk_monitoring import page
    return page(db, current_user.id, SecurityEvent, DetectionRead, employee_id=employee_id,
                start=start, end=end, limit=limit, offset=offset,
                severity=severity, event_type=event_type, incident_status=incident_status)


@router.get("/timeline")
def security_timeline(
    employee_id: str | None = None, session_ref: str | None = None,
    category: str | None = Query(default=None, pattern="^(ACCESS_ALLOWED|ACCESS_DENIED|DATA_DISCLOSED|SECURITY_DETECTION|RISK_ASSESSMENT|INCIDENT_CREATED|INCIDENT_UPDATED|AUDIT_EVENT)$"),
    severity: str | None = None, start: datetime | None = None, end: datetime | None = None,
    limit: int = Query(default=25, ge=1, le=100), offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db),
):
    from app.services.security_console import timeline
    return timeline(db, current_user.id, employee_id=employee_id, session_ref=session_ref,
                    category=category, severity=severity, start=start, end=end, limit=limit, offset=offset)


@router.get("/risk-assessments")
def risk_assessments(
    employee_id: str | None = None,
    scope: str | None = Query(default=None, pattern="^(REQUEST|SESSION|EMPLOYEE)$"),
    scope_key: str | None = None, start: datetime | None = None, end: datetime | None = None,
    limit: int = Query(default=25, ge=1, le=100), offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db),
):
    from app.models import RiskAssessment
    from app.schemas.risk import RiskRead
    from app.services.risk_monitoring import page
    return page(db, current_user.id, RiskAssessment, RiskRead, employee_id=employee_id,
                scope=scope, scope_key=scope_key, start=start, end=end, limit=limit, offset=offset)


@router.get("/risk/employees/{employee_id}")
def employee_risk(
    employee_id: str, start: datetime | None = None, end: datetime | None = None,
    limit: int = Query(default=25, ge=1, le=100), offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db),
):
    result = risk_assessments(employee_id, "EMPLOYEE", None, start, end, limit, offset, current_user, db)
    latest = risk_assessments(employee_id, "EMPLOYEE", None, start, end, 1, 0, current_user, db)["items"]
    return {**result, "latest": latest[0] if latest else None}


@router.get("/risk/sessions/{session_ref}")
def session_risk(
    session_ref: str, start: datetime | None = None, end: datetime | None = None,
    limit: int = Query(default=25, ge=1, le=100), offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db),
):
    result = risk_assessments(None, "SESSION", session_ref, start, end, limit, offset, current_user, db)
    latest = risk_assessments(None, "SESSION", session_ref, start, end, 1, 0, current_user, db)["items"]
    return {**result, "latest": latest[0] if latest else None}


@router.get("/exposure/summary")
def exposure_summary(
    start: datetime | None = None, end: datetime | None = None, session_ref: str | None = None,
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db),
):
    from app.services.exposure_service import filtered_disclosures, summarize
    return summarize(db, filtered_disclosures(db, current_user.id, start=start, end=end, session_ref=session_ref))


@router.get("/exposure/employees/{employee_id}")
def employee_exposure(
    employee_id: str, start: datetime | None = None, end: datetime | None = None,
    session_ref: str | None = None,
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db),
):
    from app.services.exposure_service import filtered_disclosures, summarize
    return summarize(db, filtered_disclosures(db, current_user.id, employee_id=employee_id,
                                             start=start, end=end, session_ref=session_ref))


@router.get("/exposure/events")
def exposure_events(
    employee_id: str | None = None, start: datetime | None = None, end: datetime | None = None,
    session_ref: str | None = None, limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db),
):
    from sqlalchemy import func, select
    from app.models import DataDisclosure
    from app.schemas.exposure import DisclosureRead
    from app.services.exposure_service import filtered_disclosures
    query = filtered_disclosures(db, current_user.id, employee_id=employee_id, start=start, end=end, session_ref=session_ref)
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    rows = db.scalars(query.order_by(DataDisclosure.timestamp.desc(), DataDisclosure.id.desc()).offset(offset).limit(limit)).all()
    return {"total": total, "limit": limit, "offset": offset,
            "items": [DisclosureRead.model_validate(row).model_dump(mode="json") for row in rows]}


@router.get("/audit-logs", response_model=list[AuditEventRead])
def get_audit_logs(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[AuditEventRead]:
    return admin.audit_query(db, current_user.id).order_by(AuditEvent.timestamp.desc()).all()


@router.get("/security-events", response_model=list[SecurityEventRead])
def get_security_events(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[SecurityEventRead]:
    return admin.security_query(db, current_user.id).order_by(SecurityEvent.timestamp.desc()).all()
