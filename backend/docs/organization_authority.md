# Unit 3: central organizational authority

This service evaluates the organizational component of authorization only. It is
not authentication, MFA assurance, a business-data permission, an approval command,
or permission to execute an arbitrary mutation. Existing endpoints, AI tools and
frontend consumers remain unchanged until their separately approved migration.

## Complete action matrix

`AdministrativeAction`, `ScopeKind` and the immutable `ACTION_MATRIX` in
`app/services/organization_authority.py` are the executable policy definition.
EMPLOYEE has no administrative action. All actions deny inactive users and NULL or
invalid canonical roles. Legacy `User.role` is never queried or used as a fallback.

| Action | Scope kind | Permitted roles |
|---|---|---|
| ORGANIZATION_ADMINISTER | ORGANIZATION | SUPER_ADMIN |
| IDENTITY_ADMINISTER | ORGANIZATION | SUPER_ADMIN |
| DEPARTMENT_ASSIGNMENTS_ADMINISTER | ORGANIZATION | SUPER_ADMIN |
| ORGANIZATION_SECURITY_MONITOR | ORGANIZATION | SUPER_ADMIN |
| DEPARTMENT_ADMINISTER | DEPARTMENT | SUPER_ADMIN, DEPARTMENT_ADMIN |
| ACCESS_REQUEST_APPROVE | ACCESS_REQUEST | SUPER_ADMIN, DEPARTMENT_ADMIN |
| ACCESS_REQUEST_REJECT | ACCESS_REQUEST | SUPER_ADMIN, DEPARTMENT_ADMIN |
| DEPARTMENT_RESOURCE_ADMINISTER | DEPARTMENT | SUPER_ADMIN, DEPARTMENT_ADMIN |
| DEPARTMENT_GRANT_ADMINISTER | DEPARTMENT | SUPER_ADMIN, DEPARTMENT_ADMIN |
| DEPARTMENT_SECURITY_MONITOR | DEPARTMENT | SUPER_ADMIN, DEPARTMENT_ADMIN |
| DEPARTMENT_INCIDENT_INVESTIGATE | DEPARTMENT | SUPER_ADMIN, DEPARTMENT_ADMIN |

An organization action is a specific administrative purpose, not a wildcard for
other purposes. Department actions require a real department even for Super Admin.
Super Admin needs no assignment. Department Admin requires an explicit matching
assignment with `revoked_at` and `revoked_by` both NULL and `assigned_at` no later
than the current UTC time. Home department, ownership, incident reporter/assignee,
job title and grants do not establish administration. Assignments cannot elevate
EMPLOYEE, NULL or invalid roles. Managing every department does not make a Department
Admin eligible for organization-only actions.

## Scope and evaluation

- `OrganizationScope()` is required for organization actions.
- `DepartmentScope(department_id)` is required for department actions. The consumer
  must derive this from the actual server-side target, not trust a request parameter.
- `AccessRequestScope(request_id, expected_department_id=None)` is required for
  approval/rejection. The service loads the actual requester and resource-owning
  department. A mismatched expected department denies; it never overrides the
  database department. A raw department scope cannot skip the requester lookup.

Evaluation validates the action, reads active/canonical identity using scalar SQL,
resolves the typed scope, applies self-approval prohibition and role restrictions,
then reads current assignment evidence. Scalar queries bypass stale ORM objects,
relationships and JWT/frontend claims. Invalid stored Enum values are handled as
explicit denial rather than accidentally falling back to a legacy role.

No role may approve its own access request. Self-rejection is not prohibited by
the finalized self-approval rule; it still requires the proper administrative role
and department authority. Pending status, requested permission, expiry and other
workflow validation remain separate caller responsibilities. Organizational ALLOW
does not mean that an already completed request may be approved again.

The immutable `AuthorityDecision` contains allowed/denied, stable `AuthorityReason`,
actor ID, typed action, scope kind, required department ID, and matching assignment
ID/department/creation time when relevant. Its `explanation` property provides a
bounded human-readable reason. No password hashes, names, legacy roles, business
records, request justifications, other users' assignment histories or secrets are
returned. This is an internal decision, not an automatic public API response;
future consumers must still minimize response information.

No decisions are cached across calls. Ordinary evaluation does not flush, write,
audit or commit. It reads persisted state, not unflushed caller ORM edits. After a
revocation/demotion commits, subsequent read-committed checks observe the new state.

## Authentication and trusted-principal integration

The typed `TrustedPrincipalContext` protocol declares only `subject_user_id` and
an opaque `authentication_context_id`. It defines an upstream integration contract;
there is deliberately no issuer or implementation in Unit 3. An object satisfying
the protocol, a context ID, or an authority ALLOW does not prove authentication.

Production consumers must obtain the actor from a trusted authentication boundary.
After Units 5/6 that boundary must validate the server-tracked session, subject,
expiry, revocation, current credential generation and required TOTP assurance in
the backend before calling organizational policy. Do not accept a raw user ID,
role, assignment, context string or MFA boolean from an HTTP request as that proof.

Current password-only JWTs are not considered MFA-verified. Unit 3 does not modify
`get_current_user`, issue sessions, create an MFA flag, or wire any existing endpoint
to this incomplete integration. Unit 4 and the authentication cutover require their
own review. All canonical roles retain ordinary employee functionality through
separate employee/data-access policies.

Business-data operations (`read`, `write`, `export`, etc.) are not administrative
actions. Unknown actions deny even for Super Admin. Existing `evaluate_access()`
behavior, including the separately deferred Option B ownership change, is untouched.
There is no emergency override or administrative data-access bypass.

## Transaction-aware revalidation

`revalidate_authority_for_mutation()` requires an explicit caller-owned
`with session.begin():` transaction and no pending new/dirty/deleted ORM state.
It does not turn an implicit SQLAlchemy autobegin into an explicit transaction.

The method first evaluates policy, then reuses Unit 2's `lock_identity()` on the
actor, and evaluates again after locking. A preliminary ALLOW is never returned
without the final read. Unit 2 role/assignment mutations lock that same user row,
so cooperating writers cannot revoke/demote the actor and commit while its sensitive
operation still holds the lock. SQLite takes its write lock; PostgreSQL takes the
user-row write lock. No separate lock framework or stale-revision bypass is added.

For request actions the service also locks the request and resource rows and
re-resolves their current requester/department. For other department actions it
locks the department row, but the caller must also lock the actual business target
and derive/verify its department in the same transaction before mutation. A check
for department A never authorizes changing a resource/grant/incident in department B.
Cross-department evidence must be checked per department; no single department
ALLOW grants organization-wide evidence visibility.

Future sensitive consumer sequence:

1. Establish a trusted authenticated principal (and mandatory server-validated MFA
   after Unit 6) and the caller-owned transaction boundary.
2. Lock actual mutation targets and verify scope. Coordinate multi-user identity
   locks in a stable order to avoid conflicting lock orders.
3. Revalidate authority for the actual actor/action/scope.
4. Reject DENY before any sensitive mutation.
5. Apply workflow invariants and Unit 2 expected-revision checks where applicable.
6. Mutate and append required audit evidence in the same transaction; caller commits.

Do not retain an ALLOW for later requests/transactions or across a commit that
releases locks. Do not bypass Unit 2 revision checks merely because authority passed.
Database errors, deadlocks and serialization failures never imply ALLOW; roll back
and retry from fresh state where safe. For consistent multi-row reads use the
transaction-aware path and appropriate isolation. Repeatable-read snapshots are
not a substitute for fresh mutation revalidation.

The guarantees cover cooperating Unit 2 identity writers. Direct SQL/ORM assignment
writers that bypass that protocol are outside them. Real PostgreSQL concurrent
execution has not been tested here; tests use guarded in-memory SQLite, deterministic
interleavings and offline PostgreSQL statement compilation only.

## Verification

Use the unchanged isolated test launcher:

```text
.\.venv\Scripts\python.exe -u -B backend/scripts/run_phase1_tests.py backend/tests/test_organization_authority.py -q
.\.venv\Scripts\python.exe -u -B backend/scripts/run_phase1_tests.py backend/tests -q
```

Tests cover every role/action combination, assignments, stale objects, invalid
canonical roles, legacy roles, scope binding, self-approval, data-access separation,
explanations, transaction ownership and revalidation after identity/scope changes.
No project migration or live backfill is run.
