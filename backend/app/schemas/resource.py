from pydantic import BaseModel, ConfigDict


class ResourceRead(BaseModel):
    id: str
    name: str
    description: str | None = None
    department_id: str
    owner_id: str
    sensitivity: str

    model_config = ConfigDict(from_attributes=True)