from typing import Any
import logging
from sqlalchemy.orm import Session

from app.models.audit_event import AuditEvent
from app.security.detection_engine import evaluate_detection_rules

logger = logging.getLogger("gnosis.audit")


def record_audit_event(
    db: Session,
    action: str,
    outcome: str,
    actor_id: str | None = None,
    resource_id: str | None = None,
    reason: str | None = None,
    context_data: dict[str, Any] | None = None,
) -> AuditEvent | None:
    """
    Persists historical audit event and triggers detection.
    Failsafe: Never raises exceptions or affects calling authorization/access workflows.
    """
    try:
        if action == "RESOURCE_ACCESS" and resource_id:
            from app.models import Resource
            resource = db.get(Resource, resource_id)
            if resource:
                context_data = {**(context_data or {}), "department_id": resource.department_id,
                                "sensitivity": resource.sensitivity}
        audit_event = AuditEvent(
            actor_id=actor_id,
            action=action,
            resource_id=resource_id,
            outcome=outcome,
            reason=reason,
            context_data=context_data,
        )
        db.add(audit_event)
        db.commit()
        db.refresh(audit_event)

        # Trigger detection engine
        try:
            evaluate_detection_rules(db, audit_event)
            db.commit()  # Caller owns observation transaction, never the engine.
        except Exception:
            db.rollback()
            logger.error("Detection processing failed; committed audit retained for explicit replay")

        return audit_event
    except Exception:
        logger.error("Failed to record audit event")
        db.rollback()
        return None
