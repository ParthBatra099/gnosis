"""create phase 2e access grants table

Revision ID: 0003_phase_2e
Revises: 0002_phase_2d
Create Date: 2026-09-20 14:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = '0003_phase_2e'
down_revision: Union[str, None] = '0002_phase_2d'
branch_labels: Union[Sequence[str], str, None] = None
depends_on: Union[Sequence[str], str, None] = None


def upgrade() -> None:
    op.create_table(
        'access_grants',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('resource_id', sa.String(length=36), nullable=False),
        sa.Column('permission', sa.String(length=50), nullable=False),
        sa.Column('granted_by', sa.String(length=36), nullable=True),
        sa.Column('access_request_id', sa.String(length=36), nullable=True),
        sa.Column('granted_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['access_request_id'], ['access_requests.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['granted_by'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['resource_id'], ['resources.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_access_grants_resource_id'), 'access_grants', ['resource_id'], unique=False)
    op.create_index(op.f('ix_access_grants_user_id'), 'access_grants', ['user_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_access_grants_user_id'), table_name='access_grants')
    op.drop_index(op.f('ix_access_grants_resource_id'), table_name='access_grants')
    op.drop_table('access_grants')