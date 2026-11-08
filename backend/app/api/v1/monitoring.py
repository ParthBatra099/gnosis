from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.audit_event import AuditEvent
from app.models.security_event import SecurityEvent
from app.models.user import User
from app.schemas.monitoring import AuditEventRead, SecurityEventRead
from app.services import administrative_access as admin

router = APIRouter()


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
