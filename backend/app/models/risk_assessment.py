"""Immutable observational assessments and complete evidence-department scope."""
import uuid
from datetime import datetime
from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"
    __table_args__ = (
        CheckConstraint("score >= 0 AND score <= 100", name="ck_risk_score"),
        CheckConstraint("level IN ('LOW','MEDIUM','HIGH','CRITICAL')", name="ck_risk_level"),
        CheckConstraint("scope IN ('REQUEST','SESSION','EMPLOYEE')", name="ck_risk_scope"),
        CheckConstraint("window_end >= window_start", name="ck_risk_window"),
        Index("ix_risk_actor_time", "actor_id", "timestamp"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    actor_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    scope: Mapped[str] = mapped_column(String(20), nullable=False)
    scope_key: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(30), nullable=False)
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    level: Mapped[str] = mapped_column(String(20), nullable=False)
    factors: Mapped[list] = mapped_column(JSON, nullable=False)
    evidence: Mapped[dict] = mapped_column(JSON, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class MonitoringScope(Base):
    __tablename__ = "monitoring_scopes"
    __table_args__ = (
        CheckConstraint("(security_event_id IS NOT NULL AND assessment_id IS NULL) OR (security_event_id IS NULL AND assessment_id IS NOT NULL)", name="ck_monitoring_scope_target"),
        Index("ix_monitoring_scope_event", "security_event_id"),
        Index("ix_monitoring_scope_assessment", "assessment_id"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    security_event_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("security_events.id", ondelete="RESTRICT"), nullable=True)
    assessment_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("risk_assessments.id", ondelete="RESTRICT"), nullable=True)
    # NULL means unresolved historical scope, visible only to the global monitor.
    department_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("departments.id", ondelete="RESTRICT"), nullable=True)
