from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict


class AuditEventRead(BaseModel):
    id: str
    actor_id: str | None = None
    action: str
    resource_id: str | None = None
    outcome: str
    reason: str | None = None
    context_data: dict[str, Any] | None = None
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


class SecurityEventRead(BaseModel):
    id: str
    event_type: str
    severity: str
    actor_id: str | None = None
    resource_id: str | None = None
    source_audit_id: str | None = None
    description: str
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)