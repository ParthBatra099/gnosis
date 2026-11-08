"""Validate reviewed canonical identities, then prohibit unresolved identities.

No mapping, assignment mutation or deletion occurs. The preceding nullable schema
is retained until independent review/backfill has resolved every account.
"""
from alembic import op
import sqlalchemy as sa

revision = "0010_phase2_identity_validation"
down_revision = "0009_phase2_org_management"
branch_labels = None
depends_on = None

# Kept in the revision: later application changes must not change migration checks.
# SELECT-only predicates are also exercised against disposable SQLite fixtures.
CHECKS = (
    ("Unresolved canonical roles: independently review and map every account, including inactive users.",
     "SELECT 1 FROM users WHERE organization_role IS NULL OR organization_role NOT IN ('SUPER_ADMIN', 'DEPARTMENT_ADMIN', 'EMPLOYEE')"),
    ("Invalid active assignment role: explicitly revoke assignments or review the canonical role; no automatic repair is permitted.",
     "SELECT 1 FROM department_admin_assignments a JOIN users u ON u.id=a.user_id WHERE a.revoked_at IS NULL AND u.organization_role <> 'DEPARTMENT_ADMIN'"),
    ("Orphan identity references: independently review the referenced users and departments.",
     "SELECT 1 FROM users u LEFT JOIN departments d ON d.id=u.department_id WHERE d.id IS NULL"),
    ("Orphan assignment references: preserve history and independently resolve references.",
     "SELECT 1 FROM department_admin_assignments a LEFT JOIN users u ON u.id=a.user_id LEFT JOIN departments d ON d.id=a.department_id LEFT JOIN users creator ON creator.id=a.assigned_by LEFT JOIN users revoker ON revoker.id=a.revoked_by WHERE u.id IS NULL OR d.id IS NULL OR creator.id IS NULL OR (a.revoked_by IS NOT NULL AND revoker.id IS NULL)"),
    ("Invalid revocation history: independently review the assignment evidence.",
     "SELECT 1 FROM department_admin_assignments WHERE (revoked_at IS NULL AND revoked_by IS NOT NULL) OR (revoked_at IS NOT NULL AND revoked_by IS NULL) OR revoked_at < assigned_at"),
    ("Duplicate active assignments: independently review and explicitly revoke conflicting assignments.",
     "SELECT 1 FROM department_admin_assignments WHERE revoked_at IS NULL GROUP BY user_id, department_id HAVING count(*) > 1"),
)


def upgrade():
    # Prevent cooperating and direct writers from introducing new unresolved rows
    # between validation and NOT NULL enforcement. PostgreSQL transaction owns locks.
    op.execute("LOCK TABLE users, departments, department_admin_assignments IN SHARE ROW EXCLUSIVE MODE")
    for message, query in CHECKS:
        escaped = message.replace("'", "''")
        op.execute(sa.text("DO $identity_validation$ BEGIN IF EXISTS (" + query +
                           ") THEN RAISE EXCEPTION '" + escaped +
                           "'; END IF; END; $identity_validation$;"))
    op.alter_column("users", "organization_role", existing_type=sa.String(50), nullable=False)


def downgrade():
    raise RuntimeError("Identity validation downgrade is unsupported; retain reviewed identities and security history. Use compatible application rollback or approved recovery.")
