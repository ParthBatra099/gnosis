"""create phase 2d access requests table

Revision ID: 0002_phase_2d
Revises: 0001_phase_2a
Create Date: 2026-09-20 14:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = '0002_phase_2d'
down_revision: Union[str, None] = '0001_phase_2a'
branch_labels: Union[Sequence[str], str, None] = None
depends_on: Union[Sequence[str], str, None] = None


def upgrade() -> None:
    op.create_table(
        'access_requests',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('requester_id', sa.String(length=36), nullable=False),
        sa.Column('resource_id', sa.String(length=36), nullable=False),
        sa.Column('permission', sa.String(length=50), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['requester_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['resource_id'], ['resources.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_access_requests_requester_id'), 'access_requests', ['requester_id'], unique=False)
    op.create_index(op.f('ix_access_requests_resource_id'), 'access_requests', ['resource_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_access_requests_resource_id'), table_name='access_requests')
    op.drop_index(op.f('ix_access_requests_requester_id'), table_name='access_requests')
    op.drop_table('access_requests')