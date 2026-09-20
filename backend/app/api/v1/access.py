from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.access_grant import AccessGrant
from app.models.access_request import AccessRequest
from app.models.resource import Resource
from app.models.user import User
from app.schemas.access_grant import AccessGrantRead, GrantApproveRequest
from app.schemas.access_request import AccessRequestCreate, AccessRequestRead
from app.security.access_decision import SUPPORTED_PERMISSIONS, evaluate_access
from app.services.audit_service import record_audit_event

router = APIRouter()


@router.post(
    "/requests",
    response_model=AccessRequestRead,
    status_code=status.HTTP_201_CREATED,
)
def create_access_request(
    payload: AccessRequestCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> AccessRequestRead:
    """Create a new pending access request for a resource."""
    if payload.permission not in SUPPORTED_PERMISSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported permission. Must be one of: {list(SUPPORTED_PERMISSIONS)}",
        )

    resource = db.query(Resource).filter(Resource.id == payload.resource_id).first()
    if not resource:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Resource not found",
        )

    active_grants = (
        db.query(AccessGrant)
        .filter(
            AccessGrant.user_id == current_user.id,
            AccessGrant.resource_id == payload.resource_id,
            AccessGrant.permission == payload.permission,
        )
        .all()
    )

    decision = evaluate_access(
        user=current_user,
        resource=resource,
        requested_permission=payload.permission,
        active_grants=active_grants,
    )
    if decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Access already granted by security policy",
        )

    existing_pending = (
        db.query(AccessRequest)
        .filter(
            AccessRequest.requester_id == current_user.id,
            AccessRequest.resource_id == payload.resource_id,
            AccessRequest.permission == payload.permission,
            AccessRequest.status == "PENDING",
        )
        .first()
    )
    if existing_pending:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A pending access request for this resource and permission already exists",
        )

    access_req = AccessRequest(
        requester_id=current_user.id,
        resource_id=payload.resource_id,
        permission=payload.permission,
        reason=payload.reason,
        status="PENDING",
    )
    db.add(access_req)
    db.commit()
    db.refresh(access_req)

    record_audit_event(
        db=db,
        action="ACCESS_REQUEST_CREATED",
        outcome="ALLOW",
        actor_id=current_user.id,
        resource_id=resource.id,
        reason="REQUEST_SUBMITTED",
        context_data={"request_id": access_req.id, "permission": payload.permission},
    )

    return access_req


@router.get("/requests/me", response_model=list[AccessRequestRead])
def get_my_access_requests(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[AccessRequestRead]:
    return (
        db.query(AccessRequest)
        .filter(AccessRequest.requester_id == current_user.id)
        .order_by(AccessRequest.created_at.desc())
        .all()
    )


@router.get("/requests/pending-approvals", response_model=list[AccessRequestRead])
def get_pending_approvals_for_owner(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[AccessRequestRead]:
    return (
        db.query(AccessRequest)
        .join(Resource, AccessRequest.resource_id == Resource.id)
        .filter(
            Resource.owner_id == current_user.id,
            AccessRequest.status == "PENDING",
        )
        .order_by(AccessRequest.created_at.desc())
        .all()
    )


@router.post("/requests/{request_id}/approve", response_model=AccessGrantRead)
def approve_access_request(
    request_id: str,
    payload: GrantApproveRequest | None = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> AccessGrantRead:
    access_req = db.query(AccessRequest).filter(AccessRequest.id == request_id).first()
    if not access_req:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Access request not found",
        )

    resource = db.query(Resource).filter(Resource.id == access_req.resource_id).first()
    if not resource or resource.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the resource owner can approve access requests for this resource",
        )

    if access_req.status != "PENDING":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot approve a request with status '{access_req.status}'",
        )

    expires_at_val = payload.expires_at if payload else None
    if expires_at_val is not None:
        if expires_at_val.tzinfo is None:
            expires_at_val = expires_at_val.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        if expires_at_val <= now:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="expires_at must be in the future",
            )

    access_req.status = "APPROVED"

    grant = AccessGrant(
        user_id=access_req.requester_id,
        resource_id=access_req.resource_id,
        permission=access_req.permission,
        granted_by=current_user.id,
        access_request_id=access_req.id,
        expires_at=expires_at_val,
    )
    db.add(grant)
    db.commit()
    db.refresh(grant)

    record_audit_event(
        db=db,
        action="ACCESS_REQUEST_APPROVED",
        outcome="ALLOW",
        actor_id=current_user.id,
        resource_id=resource.id,
        reason="OWNER_APPROVED",
        context_data={"grant_id": grant.id, "request_id": access_req.id},
    )

    return grant


@router.post("/requests/{request_id}/reject", response_model=AccessRequestRead)
def reject_access_request(
    request_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> AccessRequestRead:
    access_req = db.query(AccessRequest).filter(AccessRequest.id == request_id).first()
    if not access_req:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Access request not found",
        )

    resource = db.query(Resource).filter(Resource.id == access_req.resource_id).first()
    if not resource or resource.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the resource owner can reject access requests for this resource",
        )

    if access_req.status != "PENDING":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot reject a request with status '{access_req.status}'",
        )

    access_req.status = "REJECTED"
    db.commit()
    db.refresh(access_req)

    record_audit_event(
        db=db,
        action="ACCESS_REQUEST_REJECTED",
        outcome="ALLOW",
        actor_id=current_user.id,
        resource_id=resource.id,
        reason="OWNER_REJECTED",
        context_data={"request_id": access_req.id},
    )

    return access_req


@router.get("/grants/me", response_model=list[AccessGrantRead])
def get_my_access_grants(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[AccessGrantRead]:
    return (
        db.query(AccessGrant)
        .filter(AccessGrant.user_id == current_user.id)
        .order_by(AccessGrant.granted_at.desc())
        .all()
    )


@router.get("/grants/owned", response_model=list[AccessGrantRead])
def get_owned_resources_access_grants(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[AccessGrantRead]:
    return (
        db.query(AccessGrant)
        .join(Resource, AccessGrant.resource_id == Resource.id)
        .filter(Resource.owner_id == current_user.id)
        .order_by(AccessGrant.granted_at.desc())
        .all()
    )


@router.post("/grants/{grant_id}/revoke", response_model=AccessGrantRead)
def revoke_access_grant(
    grant_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> AccessGrantRead:
    grant = db.query(AccessGrant).filter(AccessGrant.id == grant_id).first()
    if not grant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Access grant not found",
        )

    resource = db.query(Resource).filter(Resource.id == grant.resource_id).first()
    if not resource or resource.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the resource owner can revoke access grants for this resource",
        )

    if grant.revoked_at is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Grant is already revoked",
        )

    grant.revoked_at = datetime.now(timezone.utc)
    grant.revoked_by = current_user.id
    db.commit()
    db.refresh(grant)

    record_audit_event(
        db=db,
        action="GRANT_REVOKED",
        outcome="ALLOW",
        actor_id=current_user.id,
        resource_id=resource.id,
        reason="OWNER_REVOKED",
        context_data={"grant_id": grant.id},
    )

    return grant