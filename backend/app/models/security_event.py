from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base

if TYPE_CHECKING:
    from app.models.audit_event import AuditEvent
    from app.models.resource import Resource
    from app.models.user import User


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    actor_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    resource_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("resources.id", ondelete="SET NULL"), nullable=True
    )
    source_audit_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("audit_events.id", ondelete="SET NULL"), nullable=True
    )
    description: Mapped[str] = mapped_column(Text, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    actor: Mapped[User | None] = relationship("User", foreign_keys=[actor_id])
    resource: Mapped[Resource | None] = relationship("Resource", foreign_keys=[resource_id])
    source_audit: Mapped[AuditEvent | None] = relationship("AuditEvent")