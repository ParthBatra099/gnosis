from datetime import datetime
from pydantic import BaseModel, ConfigDict
from app.schemas.monitoring import SecurityEventRead


class DetectionRead(SecurityEventRead):
    evidence: dict | None


class RiskRead(BaseModel):
    id: str
    actor_id: str
    scope: str
    scope_key: str
    policy_version: str
    score: int
    level: str
    factors: list[dict]
    evidence: dict
    timestamp: datetime
    window_start: datetime
    window_end: datetime
    model_config = ConfigDict(from_attributes=True)
