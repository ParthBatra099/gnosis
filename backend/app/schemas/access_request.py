from datetime import datetime
from pydantic import BaseModel, ConfigDict


class AccessRequestCreate(BaseModel):
    resource_id: str
    permission: str
    reason: str


class AccessRequestRead(BaseModel):
    id: str
    requester_id: str
    resource_id: str
    permission: str
    reason: str
    status: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)