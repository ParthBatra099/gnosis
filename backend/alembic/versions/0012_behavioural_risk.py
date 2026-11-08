"""Add observational detection episodes and risk evidence; preserve historical rows."""
from alembic import op
import sqlalchemy as sa

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("security_events", sa.Column("episode_key", sa.String(64), nullable=True))
    op.add_column("security_events", sa.Column("evidence", sa.JSON(), nullable=True))
    op.create_unique_constraint("uq_security_events_episode_key", "security_events", ["episode_key"])
    op.create_table("risk_assessments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("fingerprint", sa.String(64), nullable=False, unique=True),
        sa.Column("actor_id", sa.String(36), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("scope", sa.String(20), nullable=False),
        sa.Column("scope_key", sa.String(64), nullable=False),
        sa.Column("policy_version", sa.String(30), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("level", sa.String(20), nullable=False),
        sa.Column("factors", sa.JSON(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("score >= 0 AND score <= 100", name="ck_risk_score"),
        sa.CheckConstraint("level IN ('LOW','MEDIUM','HIGH','CRITICAL')", name="ck_risk_level"),
        sa.CheckConstraint("scope IN ('REQUEST','SESSION','EMPLOYEE')", name="ck_risk_scope"),
        sa.CheckConstraint("window_end >= window_start", name="ck_risk_window"))
    op.create_index("ix_risk_actor_time", "risk_assessments", ["actor_id", "timestamp"])
    op.create_table("monitoring_scopes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("security_event_id", sa.String(36), sa.ForeignKey("security_events.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("assessment_id", sa.String(36), sa.ForeignKey("risk_assessments.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("department_id", sa.String(36), sa.ForeignKey("departments.id", ondelete="RESTRICT"), nullable=True),
        sa.CheckConstraint("(security_event_id IS NOT NULL AND assessment_id IS NULL) OR (security_event_id IS NULL AND assessment_id IS NOT NULL)", name="ck_monitoring_scope_target"))
    op.create_index("ix_monitoring_scope_event", "monitoring_scopes", ["security_event_id"])
    op.create_index("ix_monitoring_scope_assessment", "monitoring_scopes", ["assessment_id"])


def downgrade():
    raise RuntimeError("Preserve risk and detection evidence; use reviewed backup recovery or forward fix")
