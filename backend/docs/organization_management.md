# Unit 7 organization management

Unit 10B adds Super-Admin-only employee session inventory/revocation and final
identity validation after reviewed backfill. See [phase2_unit10b.md](phase2_unit10b.md)
for the exact contract, 0010 dependency and deployment ordering. New employee
creation now inserts explicit canonical EMPLOYEE without a transient null; its
inactive/onboarding boundary is unchanged. Recent-TOTP policy remains deferred.

## Schema and onboarding decisions (recorded before implementation)

Department has no lifecycle field. Soft deactivation therefore requires additive
revision `0009_phase2_org_management`, extending verified head
`0008_phase2_authentication`, adding `departments.active` with default true and a
unique index over lower(trim(name)). This preserves existing behavior/history.
No existing migration is rewritten or applied. Deployment must review normalized
name collisions before applying the index; the migration must fail rather than
silently rename or delete duplicates. Deactivation is restricted to departments
without resources, active home-department users or active admin assignments.

There is no trusted password setup/onboarding service, only seed scripts. Employee
creation will create an inactive, explicitly canonical EMPLOYEE identity using a
discarded random password hash. No password is disclosed and no authentication
state, session, MFA credential or recovery code is issued. A trusted onboarding
process remains required. Reactivation is limited to previously enrolled accounts
with active MFA and an active home department. This does not authorize first
enrollment, create a bootstrap Super Admin or bypass the Unit 6 authorizer.

## API authority matrix

Prefix: `/organization`. Every route uses Unit 6 authentication/CSRF unchanged.

| Method/path | Unit 3 action/scope |
|---|---|
| GET `/departments` | ORGANIZATION_ADMINISTER/OrganizationScope or per-row DEPARTMENT_ADMINISTER/DepartmentScope |
| GET `/departments/{id}` | Same; target ID filtered by permitted departments |
| POST `/departments` | ORGANIZATION_ADMINISTER/OrganizationScope |
| PATCH `/departments/{id}` | ORGANIZATION_ADMINISTER/OrganizationScope |
| POST `/departments/{id}/deactivate` | ORGANIZATION_ADMINISTER/OrganizationScope |
| POST `/departments/{id}/reactivate` | ORGANIZATION_ADMINISTER/OrganizationScope |
| GET `/departments/{id}/assignments` | DEPARTMENT_ASSIGNMENTS_ADMINISTER/OrganizationScope or DEPARTMENT_ADMINISTER/actual DepartmentScope |
| GET `/employees` | IDENTITY_ADMINISTER/OrganizationScope or DEPARTMENT_ADMINISTER for actual home departments |
| GET `/employees/{id}` | Same, actual persisted home-department scope |
| POST `/employees` | IDENTITY_ADMINISTER/OrganizationScope; inactive canonical EMPLOYEE only |
| PATCH `/employees/{id}` | IDENTITY_ADMINISTER/OrganizationScope |
| POST `/employees/{id}/role` | IDENTITY_ADMINISTER/OrganizationScope |
| POST `/employees/{id}/deactivate` | IDENTITY_ADMINISTER/OrganizationScope |
| POST `/employees/{id}/reactivate` | IDENTITY_ADMINISTER/OrganizationScope |
| GET `/employees/{id}/assignments` | DEPARTMENT_ASSIGNMENTS_ADMINISTER/OrganizationScope or home-department DEPARTMENT_ADMINISTER plus scoped assignment rows |
| GET `/assignments` | DEPARTMENT_ASSIGNMENTS_ADMINISTER/OrganizationScope |
| POST `/assignments` | DEPARTMENT_ASSIGNMENTS_ADMINISTER/OrganizationScope |
| POST `/assignments/{id}/revoke` | DEPARTMENT_ASSIGNMENTS_ADMINISTER/OrganizationScope |

## Requests and minimal responses

All bodies forbid unknown fields. Mutations require a bounded, nonempty `reason`;
the operator must never put credentials or secrets in that reason. Existing-target
changes also require the latest opaque `expected_revision` (64 lowercase hex
characters) from the corresponding profile/assignment/department response. It is
optimistic concurrency metadata, not proof of authorization. Paths are bounded to
the existing 36-character identifiers; clients cannot choose new primary keys.

| Request | Allowed fields in addition to reason/revision |
|---|---|
| Department create | name (1–100), optional description (up to 4000); no caller ID or active flag |
| Department patch | name and/or description; explicit null description clears it |
| Department lifecycle | No arbitrary fields; separate deactivate/reactivate commands |
| Employee create | name, valid email, home_department_id; canonical EMPLOYEE/inactive selected by the server |
| Employee patch | name, email and/or home_department_id; no role, active, password or security-generation assignment |
| Role change | organization_role, exactly SUPER_ADMIN / DEPARTMENT_ADMIN / EMPLOYEE |
| Account lifecycle | Separate deactivate/reactivate commands |
| Assignment create | user_id and department_id; explicit reviewed target identity revision |
| Assignment revoke | Target from persisted assignment ID, with its user's current revision |

Lists use `limit` (1–100, default 50), `offset` (0–100000), stable ordering and
`{items, total, limit, offset}` responses. Department search matches names;
employee search matches name/email with literal wildcard escaping. Both support
active filters; employees support home_department_id; the Super Admin assignment
list supports user_id/department_id and active/history filters. Scope WHERE clauses
are applied before search, filters, counts, ordering and pagination. Empty results
do not reveal unassigned departments/employees. Unknown and out-of-scope details
both return 404; an actor with no applicable administrative action gets 403.

Department responses contain id/name/description/active/revision. Employee
responses contain id/name/email/canonical organization_role/home_department_id/
active/revision, with `requires_trusted_onboarding: true` on creation. Assignment
responses contain id/user_id/department_id/assigned_at/assigned_by/revoked_at/
revoked_by and the target identity revision. Home membership is never conflated
with department administration. No password/hash, MFA secret/state, recovery hash,
raw token, session ID or security generation is returned.

Domain errors use `detail.code`: NOT_FOUND, STALE_REVISION, IDENTITY_INVARIANT,
IDENTITY_CONFLICT, DUPLICATE_DEPARTMENT, DUPLICATE_EMPLOYEE,
DUPLICATE_ACTIVE_ASSIGNMENT, ASSIGNMENT_ALREADY_REVOKED, DEPARTMENT_INACTIVE,
DEPARTMENT_HAS_LIVE_REFERENCES, TRUSTED_ACCOUNT_SETUP_REQUIRED,
LAST_SUPER_ADMIN_PROTECTED, SELF_ASSIGNMENT_PROHIBITED and
SELF_SCOPE_CHANGE_PROHIBITED. Unit 3 authority reason codes are retained for its
denials. Invalid bodies/query/path parameters return sanitized INVALID_INPUT (422)
without echoing forbidden credential input; unexpected failures return
SERVICE_UNAVAILABLE (503). Unit 6 authentication/transport errors remain unchanged.
Responses are no-store. No exception or authority failure falls back to ownership,
legacy role, home department or frontend claims.

## Read scope and authority

All actor identity comes from Unit 6's persisted MFA-session dependency.
Organization-wide capabilities use the existing Unit 3 OrganizationScope actions;
otherwise Unit 3 evaluates DEPARTMENT_ADMINISTER for each actual department.
Department Admin sees only its current explicitly assigned departments and users
whose persisted home_department_id is in that allowed set. Owning resources,
being an employee of a department or receiving grants does not authorize these APIs.

For departmental assignment rosters, only authorized department rows are returned.
Employee assignment detail requires both visibility of the employee's home
department and scope over each returned assignment's department. A departmental
administrator can therefore see a colleague's organizational profile without
seeing that colleague's administrative assignments in an unrelated department.
Totals/counts follow the same restriction. The organization-wide assignment list
is Super Admin only. Caller-supplied filters intersect scope and never establish it.

The new lifecycle is enforced centrally: Unit 3 returns INACTIVE_DEPARTMENT for
department/request actions against inactive departments, without changing the
role/action matrix. Unit 2 assignment creation locks/checks department activity as
well. Super Admin organization-level management/history reads can still view and
reactivate inactive departments. Existing Unit 4 response contracts do not change;
departmental administrative access to an inactive department fails closed. The
API prevents deactivation with resources/live users/active assignments, so normal
supported deactivation does not strand active business workflows.

## Mutations, concurrency and audit

`organization_management.mutation` creates an ordinary caller-owned SQLAlchemy
Session on the existing bind and explicit `begin`, following Unit 4's pattern.
Preliminary policy denial happens before target locking. Permitted low-frequency
organization writes lock existing user identities in stable ID order, then call
Unit 3 transaction-aware revalidation, holding the actor lock through commit.
Target user, department and assignment records are locked/reloaded and revisions
checked before mutation. No independent commit or best-effort audit helper is used.

The common identity lock set serializes cooperating organization mutations across
Super Admin actors, including the last-admin invariant and normalized identity
conflicts. This deliberately has a broad lock footprint for low-frequency admin
writes; high-cardinality deployments must assess contention. Existing Unit 2/6
writers use the same user-row locking protocol. Deadlocks/serialization/database
errors roll back and fail closed; retry only a fresh reviewed transaction. No
second transaction framework, engine, cache, advisory-lock infrastructure or new
organization lock table is introduced. Direct SQL writers bypassing these
protocols remain outside their guarantees and must not run concurrently.

Role changes and assignments use the existing Unit 2 methods. Unit 2 is extended
with audited profile, account-status and employee-creation primitives, preserving
its expected-revision and no-commit contract. The fingerprint serialization is
unchanged; the allowlisted identity-audit action set now includes these new
events. New audit IDs detect cooperating profile changes, including name/email,
and ABA changes without invalidating old reviewed manifests merely on deployment.
A subsequent identity change appropriately makes an old reviewed revision stale.
Backfill receipts/history are never rewritten. Department revisions separately
cover metadata, active state and strict department-event audit IDs.

Role/assignment changes, email/home-department changes, and account status changes
call Unit 5 generation/session invalidation in the same transaction. Name-only
changes do not revoke sessions. No-op changes do not add authority or unnecessary
security invalidation. Audit failure, including a late AUTH_GENERATION_CHANGED
failure after identity writes, rolls back the entire mutation, its audit and
session/generation changes. Audit evidence retains actor/target, prior/new values,
timestamp and reason. Assignment assigned/revoked timestamps/actors/history remain
intact; duplicate active assignments return conflict instead of silently reusing
an existing assignment. Demotion away from DEPARTMENT_ADMIN requires explicitly
revoking all active assignments first, as Unit 2 already requires.

An administrator cannot assign themselves new department authority. A Super Admin
also cannot change their own home department: existing business policies can use
home membership, so that would risk self-expanding data scope. Another authorized
Super Admin must review such a change. A last active, MFA-enrolled Super Admin
cannot be deactivated/demoted while no other active, MFA-enrolled Super Admin
remains. An unenrolled canonical Super Admin is not counted as a usable replacement.
This is a lifecycle safety invariant, not an alternative authorization service.

No User.role legacy provenance is overwritten. New inactive accounts have new
EMPLOYEE provenance by construction; existing legacy ADMIN users are never
inferred/promoted. Home moves update only the identity policy input; they do not
create grants or alter resource ownership. Existing business-data policies may
legitimately produce different decisions for a reviewed home-department change;
`evaluate_access()` itself is untouched and no Super Admin data bypass is added.

## Authentication and onboarding limitations

Every protected route calls Unit 6 unchanged, including cookie/CSRF, active user,
canonical identity, MFA, persisted session, generation, expiry and revocation.
Legacy JWTs/password-only tokens are rejected. No new endpoint issues a session,
MFA secret, recovery code, enrollment grant or password. No bootstrap Super Admin
route exists; an existing authenticated Super Admin is required to manage roles.

New accounts are inactive and have an undisclosed, discarded high-entropy random
password hash, not a usable password setup/delivery workflow. `requires_trusted_
onboarding` is an explicit limitation, not successful identity verification.
They cannot be reactivated by this API until trusted onboarding has established
active MFA. Since the repository has no trusted password-setup/activation
infrastructure for new inactive accounts, that separately reviewed onboarding
integration remains an operational prerequisite. No permissive authorizer is
created or installed. Existing enrolled accounts can be reactivated after checking
their active home department; they must authenticate again after invalidation.

Unit 5 generation invalidation also invalidates generation-bound unused recovery
codes, while retaining their hashes/history. Unit 7 deliberately does not change
that authentication contract or regenerate/reveal codes. A separately approved
authenticated inventory-regeneration workflow and corresponding deployment/user
procedure are still needed for affected users before production rollout. Do not
silently retain old-generation recovery capability or bypass Unit 6 to address it.
The initial/last-Super-Admin controlled bootstrap/recovery boundary remains as
documented in mandatory_mfa.md.

## Migration, compatibility and tests

Migration filename: `0009_phase2_organization_management.py`; its revision is
`0009_phase2_org_management` (within Alembic's 32-character version column), with
down_revision `0008_phase2_authentication`. It adds only active/default true and
the normalized unique name index. It inserts no identities, overwrites no labels,
preserves existing relationships/history and refuses destructive downgrade.
Rollback means retaining additive schema/history while reverting integration;
never reset the database. Existing normalized duplicates require explicit review
before deployment. No existing migrations are modified or applied in this unit.

The frontend is untouched. Future Unit 9 organization/navigation work should use
the matrix above, explicit lifecycle/role/assignment commands and returned opaque
revision tokens. Unit 8's MFA/cookie cutover is still required first. Existing
dashboard routes and response shapes are unchanged; inactive-department denial
is the documented central lifecycle security change. No application build,
dependency installation, risk/exposure/ML work or data-access redesign is included.

All tests use the unchanged guarded in-memory-only launcher. Prior migration-head
assertions now recognize the 0009 descendant while preserving the 0007/0008 chain
checks and all prior security assertions. New tests cover scoped SQL counts,
search/pagination, role/assignment constraints, lifecycle/history, CAS conflicts,
MFA and CSRF enforcement, typed actions, interleaved demotion, authority failure,
late audit rollback, session invalidation and no credential responses. A real
HTTP enrollment/TOTP/cookie regression reaches the new endpoints; other consumer
fixtures represent explicitly enrolled disposable test identities and do not
override the authentication dependency.

PostgreSQL DDL/index/default verification is offline and opens no PostgreSQL
connection. Actual multi-connection PostgreSQL contention/concurrency remains a
separately approved disposable-environment deployment check. SQLite row-lock
limitations are not presented as production concurrency proof.

```powershell
.\.venv\Scripts\python.exe -u -B backend/scripts/run_phase1_tests.py backend/tests/test_test_isolation.py -q
.\.venv\Scripts\python.exe -u -B backend/scripts/run_phase1_tests.py backend/tests/test_organization_management.py backend/tests/test_organization_management_migration.py -q
.\.venv\Scripts\python.exe -u -B backend/scripts/run_phase1_tests.py backend/tests -q
git diff --check
```

Final verification: pre-edit baseline 607 passed; focused Unit 7 suite 69 passed
(67 API/security regressions plus 2 offline migration checks); final full backend
suite 676 passed with the same two pre-existing Starlette/Pydantic deprecation
warnings. Isolation safeguards passed 7/7. The final full run reported 636 guarded
engines, 635 in-memory connections and 6 intentionally blocked unsafe isolation
probes. `git diff --check` passed. An initial new-test payload helper had a keyword
collision; it was corrected without changing application behavior or removing
assertions. No unrelated application failures or fixes were introduced.

The Git-visible baseline contained 185 files. Unit 7 preserves 179 byte-for-byte,
updates 6 intended files and adds 7. No existing files were deleted. Authentication
workflows, frontend, ownership/data-permission code, previous migrations and the
isolated launcher remain unchanged. No real accounts or credentials were created;
all mutation activity occurred in disposable in-memory databases. No ordinary
project database connection, migration application or backfill was performed.

## Exact Unit 7 file inventory

| File | Change |
|---|---|
| [backend/app/services/identity_service.py](D:/projects/gnosis/backend/app/services/identity_service.py) | Updated |
| [backend/app/services/organization_authority.py](D:/projects/gnosis/backend/app/services/organization_authority.py) | Updated |
| [backend/tests/test_authentication_migration.py](D:/projects/gnosis/backend/tests/test_authentication_migration.py) | Updated |
| [backend/tests/test_organization_migration.py](D:/projects/gnosis/backend/tests/test_organization_migration.py) | Updated |
| [backend/app/main.py](D:/projects/gnosis/backend/app/main.py) | Updated |
| [backend/app/models/department.py](D:/projects/gnosis/backend/app/models/department.py) | Updated |
| [backend/alembic/versions/0009_phase2_organization_management.py](D:/projects/gnosis/backend/alembic/versions/0009_phase2_organization_management.py) | Added |
| [backend/app/api/v1/organization.py](D:/projects/gnosis/backend/app/api/v1/organization.py) | Added |
| [backend/app/schemas/organization.py](D:/projects/gnosis/backend/app/schemas/organization.py) | Added |
| [backend/app/services/organization_management.py](D:/projects/gnosis/backend/app/services/organization_management.py) | Added |
| [backend/docs/organization_management.md](D:/projects/gnosis/backend/docs/organization_management.md) | Added |
| [backend/tests/test_organization_management.py](D:/projects/gnosis/backend/tests/test_organization_management.py) | Added |
| [backend/tests/test_organization_management_migration.py](D:/projects/gnosis/backend/tests/test_organization_management_migration.py) | Added |
