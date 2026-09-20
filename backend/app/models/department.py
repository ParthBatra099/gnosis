from __future__ import annotations
import uuid
from typing import TYPE_CHECKING
from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base

if TYPE_CHECKING:
    from app.models.user import User
    from app.models.resource import Resource


class Department(Base):
    __tablename__ = "departments"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    name: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    users: Mapped[list[User]] = relationship(
        "User",
        back_populates="department",
        cascade="all, delete-orphan",
    )
    resources: Mapped[list[Resource]] = relationship(
        "Resource",
        back_populates="department",
        cascade="all, delete-orphan",
    )