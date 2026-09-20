from fastapi import APIRouter, Depends
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.audit_event import AuditEvent
from app.models.resource import Resource
from app.models.security_event import SecurityEvent
from app.models.user import User
from app.schemas.monitoring import AuditEventRead, SecurityEventRead

router = APIRouter()


@router.get("/audit-logs", response_model=list[AuditEventRead])
def get_audit_logs(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[AuditEventRead]:
    """Retrieve audit logs authorized for current user (actor or owned resources)."""
    owned_resource_ids = [
        r.id for r in db.query(Resource.id).filter(Resource.owner_id == current_user.id).all()
    ]

    query = db.query(AuditEvent).filter(
        or_(
            AuditEvent.actor_id == current_user.id,
            AuditEvent.resource_id.in_(owned_resource_ids),
        )
    )

    return query.order_by(AuditEvent.timestamp.desc()).all()


@router.get("/security-events", response_model=list[SecurityEventRead])
def get_security_events(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[SecurityEventRead]:
    """Retrieve security events authorized for current user (actor or owned resources)."""
    owned_resource_ids = [
        r.id for r in db.query(Resource.id).filter(Resource.owner_id == current_user.id).all()
    ]

    query = db.query(SecurityEvent).filter(
        or_(
            SecurityEvent.actor_id == current_user.id,
            SecurityEvent.resource_id.in_(owned_resource_ids),
        )
    )

    return query.order_by(SecurityEvent.timestamp.desc()).all()