from datetime import datetime
from pydantic import BaseModel, ConfigDict


class AccessGrantRead(BaseModel):
    id: str
    user_id: str
    resource_id: str
    permission: str
    granted_by: str | None = None
    access_request_id: str | None = None
    granted_at: datetime
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    revoked_by: str | None = None

    model_config = ConfigDict(from_attributes=True)


class GrantApproveRequest(BaseModel):
    expires_at: datetime | None = None