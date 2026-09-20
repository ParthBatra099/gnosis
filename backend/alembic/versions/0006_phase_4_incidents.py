"""create phase 4 incidents and incident events tables

Revision ID: 0006_phase_4
Revises: 0005_phase_3
Create Date: 2026-09-20 17:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = '0006_phase_4'
down_revision: Union[str, None] = '0005_phase_3'
branch_labels: Union[Sequence[str], str, None] = None
depends_on: Union[Sequence[str], str, None] = None


def upgrade() -> None:
    op.create_table(
        'incidents',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('reporter_id', sa.String(length=36), nullable=True),
        sa.Column('assigned_to_id', sa.String(length=36), nullable=True),
        sa.Column('resource_id', sa.String(length=36), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('resolution_notes', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['assigned_to_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['reporter_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['resource_id'], ['resources.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_incidents_assigned_to_id'), 'incidents', ['assigned_to_id'], unique=False)
    op.create_index(op.f('ix_incidents_reporter_id'), 'incidents', ['reporter_id'], unique=False)
    op.create_index(op.f('ix_incidents_resource_id'), 'incidents', ['resource_id'], unique=False)
    op.create_index(op.f('ix_incidents_severity'), 'incidents', ['severity'], unique=False)
    op.create_index(op.f('ix_incidents_status'), 'incidents', ['status'], unique=False)

    op.create_table(
        'incident_events',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('incident_id', sa.String(length=36), nullable=False),
        sa.Column('security_event_id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['security_event_id'], ['security_events.id'], ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_incident_events_incident_id'), 'incident_events', ['incident_id'], unique=False)
    op.create_index(op.f('ix_incident_events_security_event_id'), 'incident_events', ['security_event_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_incident_events_security_event_id'), table_name='incident_events')
    op.drop_index(op.f('ix_incident_events_incident_id'), table_name='incident_events')
    op.drop_table('incident_events')
    op.drop_index(op.f('ix_incidents_status'), table_name='incidents')
    op.drop_index(op.f('ix_incidents_severity'), table_name='incidents')
    op.drop_index(op.f('ix_incidents_resource_id'), table_name='incidents')
    op.drop_index(op.f('ix_incidents_reporter_id'), table_name='incidents')
    op.drop_index(op.f('ix_incidents_assigned_to_id'), table_name='incidents')
    op.drop_table('incidents')