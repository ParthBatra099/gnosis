from __future__ import annotations
import uuid
from typing import TYPE_CHECKING
from sqlalchemy import String, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base

if TYPE_CHECKING:
    from app.models.department import Department
    from app.models.user import User


class Resource(Base):
    __tablename__ = "resources"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    name: Mapped[str] = mapped_column(String(150), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    department_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("departments.id", ondelete="RESTRICT"),
        nullable=False,
    )
    owner_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    sensitivity: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="INTERNAL",
    )

    department: Mapped[Department] = relationship(
        "Department",
        back_populates="resources",
    )
    owner: Mapped[User] = relationship(
        "User",
        back_populates="owned_resources",
    )