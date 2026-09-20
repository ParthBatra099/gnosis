from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field
from app.schemas.monitoring import SecurityEventRead


class IncidentCreate(BaseModel):
    title: str
    description: str
    severity: str
    resource_id: str | None = None
    assigned_to_id: str | None = None
    security_event_ids: list[str] | None = None


class IncidentUpdate(BaseModel):
    status: str | None = None
    assigned_to_id: str | None = None
    resolution_notes: str | None = None


class AttachEventsRequest(BaseModel):
    security_event_ids: list[str]


class IncidentRead(BaseModel):
    id: str
    title: str
    description: str
    severity: str
    status: str
    reporter_id: str | None = None
    assigned_to_id: str | None = None
    resource_id: str | None = None
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None = None
    resolution_notes: str | None = None

    model_config = ConfigDict(from_attributes=True)


class IncidentDetailRead(IncidentRead):
    security_events: list[SecurityEventRead] = Field(default_factory=list)


class DashboardSummaryRead(BaseModel):
    total_open_incidents: int
    critical_security_events: int
    pending_access_requests: int