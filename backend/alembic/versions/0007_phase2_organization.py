"""Add canonical organizational roles and explicit department-admin assignments.

Revision ID: 0007_phase2_organization
Revises: 0006_phase_4

No legacy role mapping or assignment backfill is performed.
"""

from alembic import op
import sqlalchemy as sa

revision = "0007_phase2_organization"
down_revision = "0006_phase_4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # No default: existing users remain explicitly unmapped, including legacy ADMINs.
    op.add_column("users", sa.Column("organization_role", sa.String(50), nullable=True))
    op.create_check_constraint(
        "ck_users_organization_role", "users",
        "organization_role IN ('SUPER_ADMIN', 'DEPARTMENT_ADMIN', 'EMPLOYEE')",
    )
    op.create_table(
        "department_admin_assignments",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("user_id", sa.String(36), nullable=False),
        sa.Column("department_id", sa.String(36), nullable=False),
        sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("assigned_by", sa.String(36), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(36), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["department_id"], ["departments.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["assigned_by"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["revoked_by"], ["users.id"], ondelete="RESTRICT"),
        sa.CheckConstraint(
            "(revoked_at IS NULL AND revoked_by IS NULL) OR "
            "(revoked_at IS NOT NULL AND revoked_by IS NOT NULL)",
            name="ck_department_admin_assignments_revocation_actor",
        ),
        sa.CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= assigned_at",
            name="ck_department_admin_assignments_revocation_time",
        ),
    )
    op.create_index("ix_department_admin_assignments_user_id", "department_admin_assignments", ["user_id"])
    op.create_index("ix_department_admin_assignments_department_id", "department_admin_assignments", ["department_id"])
    op.create_index(
        "uq_department_admin_assignments_active_pair", "department_admin_assignments",
        ["user_id", "department_id"], unique=True,
        postgresql_where=sa.text("revoked_at IS NULL"),
        sqlite_where=sa.text("revoked_at IS NULL"),
    )


def downgrade() -> None:
    # Dropping this storage would destroy reviewed identities and assignment history.
    raise RuntimeError("Destructive identity downgrade is unsupported; retain schema and history.")
