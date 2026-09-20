from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.access_grant import AccessGrant
from app.models.resource import Resource
from app.models.user import User
from app.schemas.resource import ResourceRead
from app.security.access_decision import evaluate_access
from app.services.audit_service import record_audit_event

router = APIRouter()


@router.get("/{resource_id}", response_model=ResourceRead)
def get_resource_by_id(
    resource_id: str,
    permission: str = Query(default="read"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ResourceRead:
    """Protected Resource Endpoint with audit logging and detection triggers."""
    resource = db.query(Resource).filter(Resource.id == resource_id).first()
    if not resource:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Resource not found",
        )

    active_grants = (
        db.query(AccessGrant)
        .filter(
            AccessGrant.user_id == current_user.id,
            AccessGrant.resource_id == resource_id,
            AccessGrant.permission == permission,
        )
        .all()
    )

    # Step 1: Decision source of truth
    decision = evaluate_access(
        user=current_user,
        resource=resource,
        requested_permission=permission,
        active_grants=active_grants,
    )

    # Step 2: Audit recording (Failsafe)
    outcome_str = "ALLOW" if decision.allowed else "DENY"
    record_audit_event(
        db=db,
        action="RESOURCE_ACCESS",
        outcome=outcome_str,
        actor_id=current_user.id,
        resource_id=resource.id,
        reason=decision.reason.value,
        context_data={"permission": permission},
    )

    # Step 3: Enforce authorization decision
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "message": "Access denied by security policy",
                "reason": decision.reason.value,
            },
        )

    return resource