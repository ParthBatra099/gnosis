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
        evaluate_detection_rules(db, audit_event)

        return audit_event
    except Exception as err:
        logger.error(f"Failed to record audit event: {err}")
        db.rollback()
        return None