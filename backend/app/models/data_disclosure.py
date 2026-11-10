"""Synthetic records and append-only application disclosure evidence."""
import uuid
from datetime import datetime, timezone

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class BusinessRecord(Base):
    __tablename__ = "business_records"
    __table_args__ = (
        CheckConstraint("sensitivity IN ('INTERNAL', 'CONFIDENTIAL', 'CRITICAL')", name="ck_business_record_sensitivity"),
    )
    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    resource_id: Mapped[str] = mapped_column(String(36), ForeignKey("resources.id", ondelete="RESTRICT"), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(50), nullable=False)
    sensitivity: Mapped[str] = mapped_column(String(20), nullable=False)
    # Fictional demonstration values only; never copied into the ledger.
    values: Mapped[dict] = mapped_column(JSON, nullable=False)


class DataDisclosure(Base):
    __tablename__ = "data_disclosures"
    __table_args__ = (
        UniqueConstraint("response_id", "record_id", name="uq_disclosure_response_record"),
        CheckConstraint("completion_state = 'APPLICATION_COMPLETE'", name="ck_disclosure_completion"),
        CheckConstraint("transport_state = 'UNKNOWN'", name="ck_disclosure_transport"),
        CheckConstraint("sensitivity IN ('INTERNAL', 'CONFIDENTIAL', 'CRITICAL')", name="ck_disclosure_sensitivity"),
        Index("ix_disclosure_scope_time", "department_id", "timestamp"),
        Index("ix_disclosure_actor_time", "actor_id", "timestamp"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    response_id: Mapped[str] = mapped_column(String(36), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(36), ForeignKey("resources.id", ondelete="RESTRICT"), nullable=False)
    record_id: Mapped[str] = mapped_column(String(80), ForeignKey("business_records.id", ondelete="RESTRICT"), nullable=False)
    department_id: Mapped[str] = mapped_column(String(36), ForeignKey("departments.id", ondelete="RESTRICT"), nullable=False)
    category: Mapped[str] = mapped_column(String(50), nullable=False)
    sensitivity: Mapped[str] = mapped_column(String(20), nullable=False)
    session_ref: Mapped[str | None] = mapped_column(String(64), nullable=True)
    completion_state: Mapped[str] = mapped_column(String(30), nullable=False, default="APPLICATION_COMPLETE")
    transport_state: Mapped[str] = mapped_column(String(20), nullable=False, default="UNKNOWN")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
