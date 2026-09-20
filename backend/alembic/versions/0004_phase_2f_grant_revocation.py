"""create phase 2f grant revocation fields

Revision ID: 0004_phase_2f
Revises: 0003_phase_2e
Create Date: 2026-09-20 15:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = '0004_phase_2f'
down_revision: Union[str, None] = '0003_phase_2e'
branch_labels: Union[Sequence[str], str, None] = None
depends_on: Union[Sequence[str], str, None] = None


def upgrade() -> None:
    op.add_column('access_grants', sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('access_grants', sa.Column('revoked_by', sa.String(length=36), nullable=True))
    op.create_foreign_key('fk_access_grants_revoked_by_users', 'access_grants', 'users', ['revoked_by'], ['id'], ondelete='SET NULL')


def downgrade() -> None:
    op.drop_constraint('fk_access_grants_revoked_by_users', 'access_grants', type_='foreignkey')
    op.drop_column('access_grants', 'revoked_by')
    op.drop_column('access_grants', 'revoked_at')