"""Add authentication foundation storage without enrolling or issuing credentials.

Revision ID: 0008_phase2_authentication
Revises: 0007_phase2_organization
"""

from alembic import op
import sqlalchemy as sa

revision = "0008_phase2_authentication"
down_revision = "0007_phase2_organization"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('user_authentication_states',
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='RESTRICT'), primary_key=True, nullable=False),
        sa.Column('security_generation', sa.Integer, nullable=False, server_default=sa.text('0')),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint('security_generation >= 0', name='ck_auth_state_generation'),
        sa.CheckConstraint('updated_at >= created_at', name='ck_auth_state_time'),
    )

    op.create_table('mfa_credentials',
        sa.Column('id', sa.String(36), primary_key=True, nullable=False),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='RESTRICT'), nullable=False),
        sa.Column('secret_ciphertext', sa.LargeBinary, nullable=False),
        sa.Column('key_version', sa.String(64), nullable=False),
        sa.Column('status', sa.String(20), nullable=False),
        sa.Column('enrolled_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('activated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revocation_reason', sa.String(64), nullable=True),
        sa.Column('last_accepted_step', sa.Integer, nullable=True),
        sa.CheckConstraint("status IN ('PENDING', 'ACTIVE', 'REVOKED')", name='ck_mfa_status'),
        sa.CheckConstraint('length(secret_ciphertext) > 28 AND length(key_version) > 0', name='ck_mfa_encrypted_secret'),
        sa.CheckConstraint('last_accepted_step IS NULL OR last_accepted_step >= 0', name='ck_mfa_step'),
        sa.CheckConstraint('activated_at IS NULL OR activated_at >= enrolled_at', name='ck_mfa_activation_time'),
        sa.CheckConstraint('revoked_at IS NULL OR revoked_at >= enrolled_at', name='ck_mfa_revocation_time'),
        sa.CheckConstraint("(status = 'PENDING' AND activated_at IS NULL AND revoked_at IS NULL AND revocation_reason IS NULL) OR (status = 'ACTIVE' AND activated_at IS NOT NULL AND revoked_at IS NULL AND revocation_reason IS NULL) OR (status = 'REVOKED' AND revoked_at IS NOT NULL AND revocation_reason IS NOT NULL)", name='ck_mfa_lifecycle'),
    )
    op.create_index('uq_mfa_active_user', 'mfa_credentials', ['user_id'], unique=True, postgresql_where=sa.text("status = 'ACTIVE'"), sqlite_where=sa.text("status = 'ACTIVE'"))
    op.create_index('uq_mfa_pending_user', 'mfa_credentials', ['user_id'], unique=True, postgresql_where=sa.text("status = 'PENDING'"), sqlite_where=sa.text("status = 'PENDING'"))
    op.create_index('ix_mfa_credentials_user_id', 'mfa_credentials', ['user_id'])

    op.create_table('authentication_challenges',
        sa.Column('id', sa.String(36), primary_key=True, nullable=False),
        sa.Column('token_hash', sa.String(64), nullable=False, unique=True),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='RESTRICT'), nullable=False),
        sa.Column('challenge_type', sa.String(32), nullable=False),
        sa.Column('purpose', sa.String(32), nullable=False),
        sa.Column('security_generation', sa.Integer, nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('consumed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('attempts', sa.Integer, nullable=False, server_default=sa.text('0')),
        sa.Column('max_attempts', sa.Integer, nullable=False),
        sa.CheckConstraint("purpose IN ('MFA_ENROLLMENT', 'MFA_VERIFICATION', 'ACCOUNT_RECOVERY', 'REPLACEMENT_ENROLLMENT')", name='ck_auth_challenge_purpose'),
        sa.CheckConstraint("(purpose = 'REPLACEMENT_ENROLLMENT' AND challenge_type = 'RECOVERY_VERIFIED') OR (purpose <> 'REPLACEMENT_ENROLLMENT' AND challenge_type = 'PASSWORD_VERIFIED')", name='ck_auth_challenge_type'),
        sa.CheckConstraint('security_generation >= 0', name='ck_auth_challenge_generation'),
        sa.CheckConstraint('attempts >= 0 AND max_attempts > 0 AND attempts <= max_attempts', name='ck_auth_challenge_attempts'),
        sa.CheckConstraint('expires_at > created_at', name='ck_auth_challenge_expiry'),
        sa.CheckConstraint('length(token_hash) = 64', name='ck_auth_challenge_hash'),
        sa.CheckConstraint('consumed_at IS NULL OR consumed_at >= created_at', name='ck_auth_challenge_consumption_time'),
        sa.CheckConstraint('revoked_at IS NULL OR revoked_at >= created_at', name='ck_auth_challenge_revocation_time'),
        sa.CheckConstraint('consumed_at IS NULL OR revoked_at IS NULL', name='ck_auth_challenge_terminal'),
    )
    op.create_index('ix_authentication_challenges_user_id', 'authentication_challenges', ['user_id'])
    op.create_index('ix_authentication_challenges_expires_at', 'authentication_challenges', ['expires_at'])

    op.create_table('authentication_sessions',
        sa.Column('id', sa.String(64), primary_key=True, nullable=False),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='RESTRICT'), nullable=False),
        sa.Column('credential_id', sa.String(36), sa.ForeignKey('mfa_credentials.id', ondelete='RESTRICT'), nullable=False),
        sa.Column('challenge_id', sa.String(36), sa.ForeignKey('authentication_challenges.id', ondelete='RESTRICT'), nullable=False, unique=True),
        sa.Column('security_generation', sa.Integer, nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_activity_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('idle_expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('mfa_verified_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('mfa_method', sa.String(20), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revocation_reason', sa.String(64), nullable=True),
        sa.CheckConstraint('length(id) >= 43', name='ck_auth_session_opaque_id'),
        sa.CheckConstraint('security_generation >= 0', name='ck_auth_session_generation'),
        sa.CheckConstraint("mfa_method = 'TOTP'", name='ck_auth_session_mfa_method'),
        sa.CheckConstraint('mfa_verified_at <= created_at', name='ck_auth_session_verification_time'),
        sa.CheckConstraint('expires_at > created_at', name='ck_auth_session_expiry'),
        sa.CheckConstraint('last_activity_at >= created_at AND last_activity_at < expires_at', name='ck_auth_session_activity'),
        sa.CheckConstraint('idle_expires_at > last_activity_at AND idle_expires_at <= expires_at', name='ck_auth_session_idle'),
        sa.CheckConstraint('(revoked_at IS NULL AND revocation_reason IS NULL) OR (revoked_at IS NOT NULL AND revocation_reason IS NOT NULL AND revoked_at >= created_at)', name='ck_auth_session_revocation'),
    )
    op.create_index('ix_authentication_sessions_user_id', 'authentication_sessions', ['user_id'])
    op.create_index('ix_authentication_sessions_expires_at', 'authentication_sessions', ['expires_at'])

    op.create_table('recovery_codes',
        sa.Column('id', sa.String(36), primary_key=True, nullable=False),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='RESTRICT'), nullable=False),
        sa.Column('code_hash', sa.String(255), nullable=False, unique=True),
        sa.Column('security_generation', sa.Integer, nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('consumed_at', sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("code_hash LIKE '$argon2id$%' AND length(code_hash) >= 80", name='ck_recovery_hash_format'),
        sa.CheckConstraint('security_generation >= 0', name='ck_recovery_generation'),
        sa.CheckConstraint('consumed_at IS NULL OR consumed_at >= created_at', name='ck_recovery_consumption_time'),
    )
    op.create_index('ix_recovery_codes_user_id', 'recovery_codes', ['user_id'])

    op.create_table('authentication_rate_limits',
        sa.Column('bucket_key', sa.String(64), primary_key=True, nullable=False),
        sa.Column('category', sa.String(32), nullable=False),
        sa.Column('attempts', sa.Integer, nullable=False),
        sa.Column('threshold', sa.Integer, nullable=False),
        sa.Column('window_seconds', sa.Integer, nullable=False),
        sa.Column('window_started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint('length(bucket_key) = 64', name='ck_auth_limit_key'),
        sa.CheckConstraint("category IN ('PASSWORD_ACCOUNT', 'PASSWORD_SOURCE', 'MFA_ACCOUNT', 'MFA_CHALLENGE', 'RECOVERY_ACCOUNT', 'RECOVERY_CHALLENGE', 'ENROLLMENT_CHALLENGE')", name='ck_auth_limit_category'),
        sa.CheckConstraint('attempts > 0 AND threshold > 0 AND attempts <= threshold + 1 AND window_seconds > 0', name='ck_auth_limit_counter'),
        sa.CheckConstraint('expires_at > window_started_at', name='ck_auth_limit_expiry'),
    )
    op.create_index('ix_authentication_rate_limits_expires_at', 'authentication_rate_limits', ['expires_at'])


def downgrade() -> None:
    raise RuntimeError("Destructive authentication downgrade is unsupported; retain credentials and history.")
