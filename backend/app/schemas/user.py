from pydantic import BaseModel, ConfigDict, EmailStr


class UserRead(BaseModel):
    id: str
    name: str
    email: EmailStr
    role: str
    department_id: str
    active: bool

    model_config = ConfigDict(from_attributes=True)