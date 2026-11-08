from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.access_grant import AccessGrant
from app.models.access_request import AccessRequest
from app.models.resource import Resource
from app.models.user import User
from app.schemas.access_grant import AccessGrantRead, GrantApproveRequest
from app.schemas.access_request import AccessRequestCreate, AccessRequestRead
from app.security.access_decision import SUPPORTED_PERMISSIONS
from app.services.audit_service import record_audit_event
from app.services import administrative_access as admin
from app.services import organization_authority as authority

router = APIRouter()


class ResourceMetadataResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    department_id: Optional[str] = None
    sensitivity: Optional[str] = None

    class Config:
        from_attributes = True


@router.get("/resources/metadata", response_model=List[ResourceMetadataResponse])
def get_resource_metadata_list(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[ResourceMetadataResponse]:
    """
    Returns high-level metadata for available resources to populate selection UI.
    Does NOT attempt resource access evaluations or log RESOURCE_ACCESS audit events.
    """
    return db.query(Resource).all()


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
            AccessGrant.revoked_at.is_(None),
            or_(
                AccessGrant.expires_at.is_(None),
                AccessGrant.expires_at > datetime.now(timezone.utc),
            ),
        )
        .all()
    )

    # An access request is a governance workflow, not an authorization check.
    # If the user already has an explicit active grant for the exact
    # resource + permission, do not create a duplicate request.
    # Policy-based ALLOW/DENY is intentionally NOT used here.
    # The authorization engine remains the source of truth when the
    # resource is actually accessed.
    if active_grants:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Access already granted for this resource and permission",
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
    return admin.pending_query(db, current_user.id).order_by(AccessRequest.created_at.desc()).all()


@router.post("/requests/{request_id}/approve", response_model=AccessGrantRead)
def approve_access_request(
    request_id: str,
    payload: GrantApproveRequest | None = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> AccessGrantRead:
    actor_id = current_user.id
    with admin.mutation_transaction(db) as tx:
        admin.require(authority.revalidate_authority_for_mutation(
            tx, actor_id, admin.A.ACCESS_REQUEST_APPROVE, authority.AccessRequestScope(request_id)))
        access_req = tx.query(AccessRequest).filter_by(id=request_id).with_for_update().populate_existing().one()
        if access_req.status != "PENDING":
            raise HTTPException(400, f"Cannot approve a request with status '{access_req.status}'")
        expires_at_val = payload.expires_at if payload else None
        if expires_at_val is not None:
            if expires_at_val.tzinfo is None:
                expires_at_val = expires_at_val.replace(tzinfo=timezone.utc)
            if expires_at_val <= datetime.now(timezone.utc):
                raise HTTPException(400, "expires_at must be in the future")
        access_req.status = "APPROVED"
        grant = AccessGrant(user_id=access_req.requester_id, resource_id=access_req.resource_id,
                            permission=access_req.permission, granted_by=actor_id,
                            access_request_id=access_req.id, expires_at=expires_at_val)
        tx.add(grant)
        tx.flush()
        admin.append_audit(tx, actor_id=actor_id, resource_id=access_req.resource_id,
                           action="ACCESS_REQUEST_APPROVED", reason="ADMIN_APPROVED",
                           context_data={"grant_id": grant.id, "request_id": access_req.id})
        result = AccessGrantRead.model_validate(grant)
    return result


@router.post("/requests/{request_id}/reject", response_model=AccessRequestRead)
def reject_access_request(
    request_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> AccessRequestRead:
    actor_id = current_user.id
    with admin.mutation_transaction(db) as tx:
        admin.require(authority.revalidate_authority_for_mutation(
            tx, actor_id, admin.A.ACCESS_REQUEST_REJECT, authority.AccessRequestScope(request_id)))
        access_req = tx.query(AccessRequest).filter_by(id=request_id).with_for_update().populate_existing().one()
        if access_req.status != "PENDING":
            raise HTTPException(400, f"Cannot reject a request with status '{access_req.status}'")
        access_req.status = "REJECTED"
        admin.append_audit(tx, actor_id=actor_id, resource_id=access_req.resource_id,
                           action="ACCESS_REQUEST_REJECTED", reason="ADMIN_REJECTED",
                           context_data={"request_id": access_req.id})
        result = AccessRequestRead.model_validate(access_req)
    return result


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
    # Historical URL retained; visibility now follows explicit administration.
    return db.query(AccessGrant).filter(admin.resource_predicate(
        db, current_user.id, admin.A.DEPARTMENT_GRANT_ADMINISTER, AccessGrant.resource_id
    )).order_by(AccessGrant.granted_at.desc()).all()


@router.post("/grants/{grant_id}/revoke", response_model=AccessGrantRead)
def revoke_access_grant(
    grant_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> AccessGrantRead:
    actor_id = current_user.id
    with admin.mutation_transaction(db) as tx:
        grant = tx.query(AccessGrant).filter_by(id=grant_id).first()
        if grant is None:
            raise HTTPException(404, "Access grant not found")
        admin.lock_resource_authority(tx, actor_id, grant.resource_id, admin.A.DEPARTMENT_GRANT_ADMINISTER)
        grant = tx.query(AccessGrant).filter_by(id=grant_id).with_for_update().populate_existing().one()
        admin.lock_resource_authority(tx, actor_id, grant.resource_id, admin.A.DEPARTMENT_GRANT_ADMINISTER)
        if grant.revoked_at is not None:
            raise HTTPException(400, "Grant is already revoked")
        grant.revoked_at = datetime.now(timezone.utc)
        grant.revoked_by = actor_id
        admin.append_audit(tx, actor_id=actor_id, resource_id=grant.resource_id,
                           action="GRANT_REVOKED", reason="ADMIN_REVOKED",
                           context_data={"grant_id": grant.id})
        result = AccessGrantRead.model_validate(grant)
    return result
