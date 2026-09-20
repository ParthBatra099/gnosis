from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class InvestigationRequest(BaseModel):
    question: str
    resource_id: str | None = None
    incident_id: str | None = None


class EvidenceItem(BaseModel):
    source_type: str
    source_id: str
    event_type: str | None = None
    severity: str | None = None
    action: str | None = None
    outcome: str | None = None
    reason: str | None = None
    timestamp: datetime
    description: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)


class InvestigationResponse(BaseModel):
    intent: str
    question: str
    summary: str
    risk_level: str
    confidence: str
    evidence: list[EvidenceItem] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)