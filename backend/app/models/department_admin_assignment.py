from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, func, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.department import Department
    from app.models.user import User


class DepartmentAdminAssignment(Base):
    """Administrative assignment history; storage alone does not confer permissions."""

    __tablename__ = "department_admin_assignments"
    __table_args__ = (
        CheckConstraint(
            "(revoked_at IS NULL AND revoked_by IS NULL) OR "
            "(revoked_at IS NOT NULL AND revoked_by IS NOT NULL)",
            name="ck_department_admin_assignments_revocation_actor",
        ),
        CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= assigned_at",
            name="ck_department_admin_assignments_revocation_time",
        ),
        Index(
            "uq_department_admin_assignments_active_pair", "user_id", "department_id",
            unique=True,
            postgresql_where=text("revoked_at IS NULL"),
            sqlite_where=text("revoked_at IS NULL"),
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True,
    )
    department_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("departments.id", ondelete="RESTRICT"), nullable=False, index=True,
    )
    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc), server_default=func.now(),
    )
    assigned_by: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=True,
    )

    user: Mapped[User] = relationship(
        "User", foreign_keys=[user_id], back_populates="department_admin_assignments",
    )
    department: Mapped[Department] = relationship("Department", back_populates="admin_assignments")
    assigned_by_user: Mapped[User] = relationship("User", foreign_keys=[assigned_by])
    revoked_by_user: Mapped[User | None] = relationship("User", foreign_keys=[revoked_by])
