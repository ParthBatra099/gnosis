from __future__ import annotations
import uuid
from typing import TYPE_CHECKING
from sqlalchemy import String, Boolean, Enum, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base
from app.core.constants import OrganizationRole

if TYPE_CHECKING:
    from app.models.department import Department
    from app.models.resource import Resource
    from app.models.department_admin_assignment import DepartmentAdminAssignment


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), nullable=False, default="EMPLOYEE")
    # Migration 0010 requires explicit reviewed canonical identity for every row.
    # The legacy role above remains provenance, never an authorization fallback.
    organization_role: Mapped[OrganizationRole] = mapped_column(
        Enum(
            OrganizationRole,
            name="ck_users_organization_role",
            native_enum=False,
            create_constraint=True,
            validate_strings=True,
            length=50,
        ),
        nullable=False,
    )
    department_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("departments.id", ondelete="RESTRICT"),
        nullable=False,
    )
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    department: Mapped[Department] = relationship(
        "Department",
        back_populates="users",
    )
    owned_resources: Mapped[list[Resource]] = relationship(
        "Resource",
        back_populates="owner",
        cascade="all, delete-orphan",
    )
    department_admin_assignments: Mapped[list[DepartmentAdminAssignment]] = relationship(
        "DepartmentAdminAssignment",
        foreign_keys="DepartmentAdminAssignment.user_id",
        back_populates="user",
        passive_deletes="all",
    )
