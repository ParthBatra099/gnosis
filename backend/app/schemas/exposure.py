from datetime import datetime
from pydantic import BaseModel, ConfigDict


class BusinessRecordRead(BaseModel):
    id: str
    category: str
    sensitivity: str
    values: dict
    model_config = ConfigDict(from_attributes=True)


class BusinessRecordsResponse(BaseModel):
    response_id: str
    resource_id: str
    records: list[BusinessRecordRead]
    disclosure_semantics: str = "APPLICATION_COMPLETE; network delivery UNKNOWN"


class DisclosureRead(BaseModel):
    id: str
    response_id: str
    actor_id: str
    resource_id: str
    record_id: str
    department_id: str
    category: str
    sensitivity: str
    session_ref: str | None
    completion_state: str
    transport_state: str
    timestamp: datetime
    model_config = ConfigDict(from_attributes=True)
