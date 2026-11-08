from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
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


@router.get("/{resource_id}/records")
def get_business_records(
    resource_id: str, request: Request,
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Bounded synthetic records; metadata endpoints retain their existing contracts."""
    import uuid
    from sqlalchemy import select
    from app.schemas.exposure import BusinessRecordRead, BusinessRecordsResponse
    from app.services.exposure_service import record_disclosures, retrieve_records

    resource = db.get(Resource, resource_id)
    if resource is None:
        raise HTTPException(404, "Resource not found")
    grants = db.scalars(select(AccessGrant).where(
        AccessGrant.user_id == current_user.id, AccessGrant.resource_id == resource_id)).all()
    decision = evaluate_access(current_user, resource, "read", grants)
    response_id = str(uuid.uuid4())
    from app.services.authentication_common import fingerprint
    session_ref = fingerprint(request.state.principal.authentication_context_id)
    record_audit_event(db, action="RESOURCE_ACCESS", outcome="ALLOW" if decision.allowed else "DENY",
                       actor_id=current_user.id, resource_id=resource.id, reason=decision.reason.value,
                       context_data={"permission": "read", "representation": "business_records",
                                     "response_id": response_id, "session_ref": session_ref})
    if not decision.allowed:
        raise HTTPException(403, "Access denied by security policy")
    records = retrieve_records(db, resource, limit=limit, offset=offset)
    try:
        payload = BusinessRecordsResponse(response_id=response_id, resource_id=resource_id,
                                          records=[BusinessRecordRead.model_validate(r) for r in records])
        # Construct the entire non-streaming response before persisting evidence.
        response = Response(content=payload.model_dump_json(), media_type="application/json",
                            headers={"Cache-Control": "no-store"})
        principal = request.state.principal
        record_disclosures(db, actor_id=current_user.id, resource=resource, records=records,
                           response_id=response_id, session_id=principal.authentication_context_id)
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(503, "Disclosure capture unavailable; no business response returned") from None
    from app.services.risk_service import monitor_disclosure
    monitor_disclosure(db, response_id)
    return response


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
