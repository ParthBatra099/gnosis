"""create phase 3 audit and security events tables

Revision ID: 0005_phase_3
Revises: 0004_phase_2f
Create Date: 2026-09-20 16:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = '0005_phase_3'
down_revision: Union[str, None] = '0004_phase_2f'
branch_labels: Union[Sequence[str], str, None] = None
depends_on: Union[Sequence[str], str, None] = None


def upgrade() -> None:
    op.create_table(
        'audit_events',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('actor_id', sa.String(length=36), nullable=True),
        sa.Column('action', sa.String(length=50), nullable=False),
        sa.Column('resource_id', sa.String(length=36), nullable=True),
        sa.Column('outcome', sa.String(length=20), nullable=False),
        sa.Column('reason', sa.String(length=50), nullable=True),
        sa.Column('context_data', sa.JSON(), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['actor_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['resource_id'], ['resources.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_audit_events_actor_id'), 'audit_events', ['actor_id'], unique=False)
    op.create_index(op.f('ix_audit_events_resource_id'), 'audit_events', ['resource_id'], unique=False)

    op.create_table(
        'security_events',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('event_type', sa.String(length=50), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('actor_id', sa.String(length=36), nullable=True),
        sa.Column('resource_id', sa.String(length=36), nullable=True),
        sa.Column('source_audit_id', sa.String(length=36), nullable=True),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['actor_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['resource_id'], ['resources.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['source_audit_id'], ['audit_events.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_security_events_actor_id'), 'security_events', ['actor_id'], unique=False)
    op.create_index(op.f('ix_security_events_severity'), 'security_events', ['severity'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_security_events_severity'), table_name='security_events')
    op.drop_index(op.f('ix_security_events_actor_id'), table_name='security_events')
    op.drop_table('security_events')
    op.drop_index(op.f('ix_audit_events_resource_id'), table_name='audit_events')
    op.drop_index(op.f('ix_audit_events_actor_id'), table_name='audit_events')
    op.drop_table('audit_events')