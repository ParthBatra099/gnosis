# Phase 2 Unit 10B implementation and review record

Scope: verified Unit 10A compatibility findings in the existing working tree.
The audit report is in the conversation; no Unit 10A audit file was created.

## Binding decisions

The user explicitly approved own-session management for all three canonical
roles and cross-user session management for Super Admin only. Department Admin
assignments do not authorize another user's sessions, even in an assigned department.
The user explicitly deferred a new recent-TOTP freshness gate pending a separate
policy specification. No freshness window or frontend verification flag is added.
Mandatory persisted MFA and existing TOTP replay rules remain enforced.

## Implemented corrections

- Application SQL echo is always disabled and bound parameters are hidden,
  independently of DEBUG. Deployment must still set DEBUG=false and provision
  reviewed keys/origins/proxies. No SQL parameter logging is enabled for troubleshooting.
- Canonical identity is non-null in final ORM metadata, with no role default.
  New employee creation inserts the explicitly intended canonical EMPLOYEE value,
  remains inactive and records the canonical initial identity in its atomic
  creation audit. Existing legacy User.role values are never overwritten.
- Assistant profile answers identify canonical organization_role or UNASSIGNED,
  never present legacy role as current organizational authority.
- Legacy demo seed entry points now fail before opening a database. Their old
  implementations are retained as historical source, not an approved provisioning
  workflow. No environment flag or role-inference bypass re-enables them.
- Initial/replacement recovery codes returned by successful MFA completion are
  retained only in memory even when profile validation temporarily fails. The
  workspace remains unauthenticated. A protected 401 clears the material through
  the existing session-ended handler. Acknowledgement without a validated profile
  clears the codes and returns to sign-in; it does not manufacture authentication.
- Corrupted login text is corrected and the existing sample admin dashboard is
  labeled as demonstration data. No business dashboard or analytics is implemented.

## Session-management contract

| Method/path | Authority | Result |
|---|---|---|
| GET `/auth/sessions` | Authenticated user, own rows only | Session page |
| POST `/auth/sessions/{session_ref}/revoke` | Authenticated user, own rows only | 204 |
| GET `/organization/employees/{user_id}/sessions` | Central IDENTITY_ADMINISTER / OrganizationScope | Session page |
| POST `/organization/employees/{user_id}/sessions/{session_ref}/revoke` | Same, revalidated inside mutation transaction | 204 |

Lists accept limit 1-100 (default 20) and offset 0-100000. Pages contain
items/total/limit/offset. Items expose only a SHA-256 management reference,
created_at, last_activity_at, expires_at, state and is_current. References cannot
authenticate and are never the raw signed JWT or session ID. State is ACTIVE,
EXPIRED, REVOKED or INVALIDATED; validity uses the persisted session validator,
including credential/generation checks. No password/MFA material or generations
are returned. The frontend displays only timestamps/state/current-session status.

Revocation bodies are exactly `{reason: <nonempty text, maximum 2000 characters>}`;
unknown fields are forbidden. Operators must exclude credentials from reasons.
Reference paths are 64 lowercase hexadecimal characters. Scope checks precede
reference matching. Ordinary users cannot use a known digest to target another
user. All requests use the existing cookie/CSRF transport, including public
authentication validation/error conventions; no bearer workaround is introduced.

Actor identity is exclusively from get_current_user. Writes lock/revalidate
current identity and the actor's persisted session. The session mutation and
strict audit share an existing-bind SQLAlchemy transaction. Audit failure rolls
back revocation. Audit evidence includes actor, target, time, cause, reason and a
digest reference. A one-session revocation leaves generation, other sessions and
recovery codes intact. Existing logout-all semantics are unchanged: it advances
generation, invalidates all sessions/challenges and makes old-generation recovery
inventory unusable. Inventory renewal is a separately reviewed operational gap.

The UI offers My sessions to every recognized canonical role. Super Admin gets
Manage employee sessions from employee details. The target route has a Super Admin
presentation guard; the backend independently authorizes every request. Revocation
requires explicit confirmation and reason, blocks duplicate submissions and
refreshes after server confirmation. Rejection removes stale session data; current
session revocation reaches the existing sign-in flow on the next validation.
Reference lookup currently streams the target user's retained session IDs in
bounded batches; very large retained histories need performance assessment before
deployment, without exposing raw IDs to the browser.

## Migration and deployment ordering

New revision file: `0010_phase2_identity_validation.py`.
Revision: `0010_phase2_identity_validation` (31 characters).
Dependency: `0009_phase2_org_management`. There is one repository head.

The PostgreSQL revision takes table locks, validates every account including
inactive accounts, rejects unresolved/invalid canonical roles, inconsistent active
assignment roles, orphan references, malformed revocations and duplicate active
assignments, then enforces NOT NULL. It contains no identity mappings, updates,
deletions, promotions or historical assignment removal. Existing three-role checks,
foreign keys and partial indexes remain in the predecessor chain.

Before deploying final constraints:

1. Back up data and required encryption-key versions through an approved process.
2. Review normalized department-name collisions before applying 0009.
3. Deploy compatible explicit-canonical account creation; stop unreviewed writers.
4. Independently review a manifest for every existing user, including inactive
   users, initial Super Admin, exact assignments/revocations and baseline revisions.
5. Execute backfill only through a separately approved trusted operational host.
   The existing repository utility STILL rejects PostgreSQL and ordinary project
   databases. Its dry-run, target restrictions, digest confirmation and external
   approval-verifier requirements are unchanged; no production adapter is invented.
6. Verify completed mappings and then apply 0010 in the separately approved target.
   Null roles cause an actionable failure; they never acquire a default role.

Unmapped identities remain denied at the existing authentication/authority
boundaries during transition. Nullable UserRead response handling remains compatible.
Downgrade deliberately refuses automatic security-history changes. Roll back to
a compatible MFA-enforcing build while retaining schema/history, or use reviewed
backup/restore recovery. Do not revert to a password-only application.

Existing tests concerning unresolved identities explicitly create the pre-0010
nullable schema. That helper changes only the copied fixture column's historical
nullability; it preserves role checks, foreign keys and indexes and cannot target
anything except in-memory SQLite. New final-schema tests verify NOT NULL directly.
Ordinary model/assistant fixtures now declare canonical EMPLOYEE explicitly; their
legacy provenance and all original assertions are preserved.

## Deferred findings and release blockers

- Recent-TOTP gate: explicitly deferred by the user.
- Trusted first enrollment, password setup and last-Super-Admin recovery: require
  real independent integrations and custody procedures; no bootstrap is added.
- Production backfill execution: target restrictions must not be relaxed here.
- Recovery-inventory renewal/generation policy: unchanged pending reviewed design.
- General network/filesystem isolation: launcher changes were explicitly excluded.
  Existing SQLAlchemy guards are preserved, not claimed to be an OS sandbox.
- PostgreSQL upgrades, schema enforcement, locking/concurrency, backup/recovery
  and live browser integration: require an approved disposable environment in 10C.
- Cookie/Origin topology: retain the documented reviewed cross-origin same-site
  HTTPS requirement; same-origin CSRF bootstrap needs separate contract review.
- Business-data ownership Option B remains deferred: evaluate_access is unchanged
  because the audit verified its owner allowance predates Phase 2. No new Super
  Admin data bypass, grant or implicit department authority is introduced.

Unit 10C must not begin until Unit 10B has been reviewed and accepted. Its supplied
instructions do not authorize an ordinary database or an unidentified PostgreSQL
target. No commit, push, deployment, real migration or real backfill occurs here.

## Exact Unit 10B file inventory

## Verification and preservation results

- Required final command from repository root:
  `.\.venv\Scripts\python.exe -u -B backend/scripts/run_phase1_tests.py backend/tests -q`
  passed 720 tests with the same two pre-existing Starlette/Pydantic warnings.
  Isolation evidence: 671 guarded engines, 670 in-memory connections, six
  intentionally rejected unsafe-target probes; allowed URL sqlite:///:memory:.
- Isolation preflight passed 7 tests. Focused migration checks passed 23 tests;
  the first session/compatibility/organization run passed 82 tests. Additional
  focused cases verify final constraints, every validation predicate, actor-session
  revalidation and strict revocation audit evidence.
- `npm test`: 87 passed, zero failed or skipped; the original 76 tests remain.
- `npm run build`: TypeScript and Vite production build passed.
- Targeted installed ESLint passed for all nine modified/new application TS/TSX
  modules. The two changed/new JavaScript test files additionally passed no-undef
  and no-unused-vars checks using the installed ESLint CLI.
- All 113 repository Python sources parsed successfully without application
  imports or generated bytecode. No Ruff/Flake8/Pylint/pycodestyle is installed;
  Python linter execution is unavailable and no dependency was installed.
- `git diff --check` passed, with Git line-ending notices only.

The intermediate backend run reported 710 passed and three failures in the old
model fixtures after the new NOT NULL declaration. Those fixtures now explicitly
declare their ordinary canonical EMPLOYEE identity while preserving legacy role
values and all relationship/uniqueness assertions. The intermediate frontend run
had two renderer errors because a new Link needed router context; the existing
render helper now supplies MemoryRouter without changing any assertions. Final
full suites pass. No unrelated application failure was silently repaired.

Before editing, SHA-256 hashes covered all 204 Git-visible files, including
pre-existing untracked work. Final delta: 35 intended files updated, 11 added,
169 existing files unchanged and none deleted. The final working tree contains
50 modified tracked files and 66 untracked files, including all earlier units.
The isolated launcher, conftest isolation, business policy, trusted backfill
service/CLI, MFA workflow implementation and dependency lockfile remain unchanged.
Branch main and the Phase 1 HEAD are retained; no commit or push was made.

The migration upgrade function was exercised only with offline PostgreSQL SQL
generation. Its validation SELECT predicates and final ORM constraints were
tested on disposable SQLite fixtures. No PostgreSQL upgrade, downgrade, lock or
concurrency execution is claimed. No ordinary database was accessed or real
identity migration/backfill performed. Unit 10C is awaiting Unit 10B acceptance
and an explicitly approved disposable environment.

## File list

Updated against the captured working-tree baseline (35 files):

- [backend/app/api/v1/organization.py](D:/projects/gnosis/backend/app/api/v1/organization.py)
- [backend/app/services/authentication_sessions.py](D:/projects/gnosis/backend/app/services/authentication_sessions.py)
- [backend/app/services/identity_service.py](D:/projects/gnosis/backend/app/services/identity_service.py)
- [backend/app/services/organization_management.py](D:/projects/gnosis/backend/app/services/organization_management.py)
- [backend/docs/identity_backfill.md](D:/projects/gnosis/backend/docs/identity_backfill.md)
- [backend/docs/mandatory_mfa.md](D:/projects/gnosis/backend/docs/mandatory_mfa.md)
- [backend/docs/organization_management.md](D:/projects/gnosis/backend/docs/organization_management.md)
- [backend/tests/test_administrative_consumers.py](D:/projects/gnosis/backend/tests/test_administrative_consumers.py)
- [backend/tests/test_authentication_infrastructure.py](D:/projects/gnosis/backend/tests/test_authentication_infrastructure.py)
- [backend/tests/test_authentication_migration.py](D:/projects/gnosis/backend/tests/test_authentication_migration.py)
- [backend/tests/test_department_admin_assignments.py](D:/projects/gnosis/backend/tests/test_department_admin_assignments.py)
- [backend/tests/test_identity_service.py](D:/projects/gnosis/backend/tests/test_identity_service.py)
- [backend/tests/test_mfa_workflows.py](D:/projects/gnosis/backend/tests/test_mfa_workflows.py)
- [backend/tests/test_organization_management.py](D:/projects/gnosis/backend/tests/test_organization_management.py)
- [backend/tests/test_organization_management_migration.py](D:/projects/gnosis/backend/tests/test_organization_management_migration.py)
- [backend/tests/test_organization_migration.py](D:/projects/gnosis/backend/tests/test_organization_migration.py)
- [frontend/AUTHENTICATION.md](D:/projects/gnosis/frontend/AUTHENTICATION.md)
- [frontend/ORGANIZATION_MANAGEMENT.md](D:/projects/gnosis/frontend/ORGANIZATION_MANAGEMENT.md)
- [frontend/src/context/authController.ts](D:/projects/gnosis/frontend/src/context/authController.ts)
- [frontend/src/pages/admin/OrganizationPage.tsx](D:/projects/gnosis/frontend/src/pages/admin/OrganizationPage.tsx)
- [frontend/tests/organization.test.mjs](D:/projects/gnosis/frontend/tests/organization.test.mjs)
- [backend/app/api/v1/auth.py](D:/projects/gnosis/backend/app/api/v1/auth.py)
- [backend/app/core/database.py](D:/projects/gnosis/backend/app/core/database.py)
- [backend/app/models/user.py](D:/projects/gnosis/backend/app/models/user.py)
- [backend/app/schemas/auth.py](D:/projects/gnosis/backend/app/schemas/auth.py)
- [backend/app/services/assistant_service.py](D:/projects/gnosis/backend/app/services/assistant_service.py)
- [backend/scripts/seed_demo_resources.py](D:/projects/gnosis/backend/scripts/seed_demo_resources.py)
- [backend/scripts/seed_demo_users.py](D:/projects/gnosis/backend/scripts/seed_demo_users.py)
- [backend/scripts/seed_full_demo_data.py](D:/projects/gnosis/backend/scripts/seed_full_demo_data.py)
- [backend/tests/test_assistant_service.py](D:/projects/gnosis/backend/tests/test_assistant_service.py)
- [backend/tests/test_models.py](D:/projects/gnosis/backend/tests/test_models.py)
- [frontend/src/components/layout/Sidebar.tsx](D:/projects/gnosis/frontend/src/components/layout/Sidebar.tsx)
- [frontend/src/pages/admin/AdminDashboard.tsx](D:/projects/gnosis/frontend/src/pages/admin/AdminDashboard.tsx)
- [frontend/src/pages/auth/Login.tsx](D:/projects/gnosis/frontend/src/pages/auth/Login.tsx)
- [frontend/src/routes/AppRoutes.tsx](D:/projects/gnosis/frontend/src/routes/AppRoutes.tsx)

Added (11 files):

- [backend/alembic/versions/0010_phase2_identity_validation.py](D:/projects/gnosis/backend/alembic/versions/0010_phase2_identity_validation.py)
- [backend/app/services/session_management.py](D:/projects/gnosis/backend/app/services/session_management.py)
- [backend/docs/phase2_unit10b.md](D:/projects/gnosis/backend/docs/phase2_unit10b.md)
- [backend/tests/identity_transition_support.py](D:/projects/gnosis/backend/tests/identity_transition_support.py)
- [backend/tests/test_compatibility_fixes.py](D:/projects/gnosis/backend/tests/test_compatibility_fixes.py)
- [backend/tests/test_identity_validation_migration.py](D:/projects/gnosis/backend/tests/test_identity_validation_migration.py)
- [backend/tests/test_session_management.py](D:/projects/gnosis/backend/tests/test_session_management.py)
- [frontend/src/api/sessions.ts](D:/projects/gnosis/frontend/src/api/sessions.ts)
- [frontend/src/pages/auth/SessionManagement.tsx](D:/projects/gnosis/frontend/src/pages/auth/SessionManagement.tsx)
- [frontend/src/pages/auth/sessionController.ts](D:/projects/gnosis/frontend/src/pages/auth/sessionController.ts)
- [frontend/tests/session-management.test.mjs](D:/projects/gnosis/frontend/tests/session-management.test.mjs)
