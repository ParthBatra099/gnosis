"""Add non-destructive department lifecycle and normalized name uniqueness.

Existing normalized collisions must be reviewed before deployment, never deleted
or renamed by migration. No identity mappings or credential state are populated.
"""
from alembic import op
import sqlalchemy as sa

revision = "0009_phase2_org_management"
down_revision = "0008_phase2_authentication"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("departments", sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()))
    op.create_index("uq_departments_name_normalized", "departments", [sa.text("lower(trim(name))")], unique=True)


def downgrade():
    raise RuntimeError("Destructive organization downgrade is unsupported; retain lifecycle and history.")
