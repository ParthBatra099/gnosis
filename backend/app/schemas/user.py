from pydantic import BaseModel, ConfigDict, EmailStr
from app.core.constants import OrganizationRole


class UserRead(BaseModel):
    id: str
    name: str
    email: EmailStr
    role: str
    organization_role: OrganizationRole | None
    department_id: str
    active: bool

    model_config = ConfigDict(from_attributes=True)
