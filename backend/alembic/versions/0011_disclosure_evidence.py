"""Add synthetic business records and application disclosure evidence; no data seed."""
from alembic import op
import sqlalchemy as sa

revision = "0011"
down_revision = "0010_phase2_identity_validation"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("business_records",
        sa.Column("id", sa.String(80), primary_key=True),
        sa.Column("resource_id", sa.String(36), sa.ForeignKey("resources.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("category", sa.String(50), nullable=False),
        sa.Column("sensitivity", sa.String(20), nullable=False),
        sa.Column("values", sa.JSON(), nullable=False),
        sa.CheckConstraint("sensitivity IN ('INTERNAL', 'CONFIDENTIAL', 'CRITICAL')", name="ck_business_record_sensitivity"))
    op.create_index("ix_business_records_resource_id", "business_records", ["resource_id"])
    op.create_table("data_disclosures",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("response_id", sa.String(36), nullable=False),
        sa.Column("actor_id", sa.String(36), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("resource_id", sa.String(36), sa.ForeignKey("resources.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("record_id", sa.String(80), sa.ForeignKey("business_records.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("department_id", sa.String(36), sa.ForeignKey("departments.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("category", sa.String(50), nullable=False),
        sa.Column("sensitivity", sa.String(20), nullable=False),
        sa.Column("session_ref", sa.String(64), nullable=True),
        sa.Column("completion_state", sa.String(30), nullable=False),
        sa.Column("transport_state", sa.String(20), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("response_id", "record_id", name="uq_disclosure_response_record"),
        sa.CheckConstraint("completion_state = 'APPLICATION_COMPLETE'", name="ck_disclosure_completion"),
        sa.CheckConstraint("transport_state = 'UNKNOWN'", name="ck_disclosure_transport"),
        sa.CheckConstraint("sensitivity IN ('INTERNAL', 'CONFIDENTIAL', 'CRITICAL')", name="ck_disclosure_sensitivity"))
    op.create_index("ix_disclosure_scope_time", "data_disclosures", ["department_id", "timestamp"])
    op.create_index("ix_disclosure_actor_time", "data_disclosures", ["actor_id", "timestamp"])


def downgrade():
    raise RuntimeError("Disclosure evidence must be preserved; use reviewed backup recovery or a forward fix")
