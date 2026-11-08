from datetime import datetime
import re
import unicodedata

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator

from app.core.constants import OrganizationRole


class StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ReasonRequest(StrictRequest):
    reason: str = Field(min_length=1, max_length=2000)

    @field_validator("reason")
    @classmethod
    def meaningful_reason(cls, value):
        if not value.strip():
            raise ValueError("Reason is required")
        return value.strip()


class IdentityMutation(ReasonRequest):
    expected_revision: str = Field(pattern=r"^[0-9a-f]{64}$")


def label(value):
    value = value.strip()
    if not value or any(unicodedata.category(char).startswith("C") for char in value):
        raise ValueError("Invalid label")
    return value


class DepartmentCreate(ReasonRequest):
    name: str = Field(min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=4000)
    _name = field_validator("name")(label)


class DepartmentMutation(ReasonRequest):
    expected_revision: str = Field(pattern=r"^[0-9a-f]{64}$")


class DepartmentUpdate(DepartmentMutation):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=4000)

    @field_validator("name")
    @classmethod
    def valid_name(cls, value):
        return label(value) if value is not None else value

    @model_validator(mode="after")
    def permitted_change(self):
        if not self.model_fields_set.intersection({"name", "description"}) or ("name" in self.model_fields_set and self.name is None):
            raise ValueError("Metadata change required")
        return self


class EmployeeCreate(ReasonRequest):
    name: str = Field(min_length=1, max_length=100)
    email: EmailStr
    home_department_id: str = Field(min_length=1, max_length=36)
    _name = field_validator("name")(label)


class EmployeeUpdate(IdentityMutation):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    email: EmailStr | None = None
    home_department_id: str | None = Field(default=None, min_length=1, max_length=36)

    @field_validator("name")
    @classmethod
    def valid_name(cls, value):
        return label(value) if value is not None else value

    @model_validator(mode="after")
    def permitted_change(self):
        fields = self.model_fields_set.intersection({"name", "email", "home_department_id"})
        if not fields or any(getattr(self, key) is None for key in fields):
            raise ValueError("Profile change required")
        return self


class RoleChange(IdentityMutation):
    organization_role: OrganizationRole


class AssignmentCreate(IdentityMutation):
    user_id: str = Field(min_length=1, max_length=36)
    department_id: str = Field(min_length=1, max_length=36)


class DepartmentRead(BaseModel):
    id: str
    name: str
    description: str | None
    active: bool
    revision: str


class EmployeeRead(BaseModel):
    id: str
    name: str
    email: str
    organization_role: OrganizationRole | None
    home_department_id: str
    active: bool
    revision: str


class EmployeeCreated(EmployeeRead):
    requires_trusted_onboarding: bool = True


class AssignmentRead(BaseModel):
    id: str
    user_id: str
    department_id: str
    assigned_at: datetime
    assigned_by: str
    revoked_at: datetime | None
    revoked_by: str | None
    revision: str


class DepartmentPage(BaseModel):
    items: list[DepartmentRead]
    total: int
    limit: int
    offset: int


class EmployeePage(BaseModel):
    items: list[EmployeeRead]
    total: int
    limit: int
    offset: int


class AssignmentPage(BaseModel):
    items: list[AssignmentRead]
    total: int
    limit: int
    offset: int
