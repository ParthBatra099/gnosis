# Phase 2 Unit 9: organization management frontend

Unit 10B adds a Super-Admin-only employee-session link and route, with backend
IDENTITY_ADMINISTER checks. Department Admin gains no cross-user session powers.
My sessions remains available to all canonical roles. Other Unit 9 boundaries below
are unchanged; see the backend Unit 10B report for the session API and final identity migration.

The inspected Unit 7 routes/schemas/services and Unit 3/4 authority documents are
the contract. This unit integrates them through the unchanged Unit 8 cookie/CSRF
client. It neither implements nor substitutes for backend authorization.

## Endpoint-to-screen contract matrix

All paths below have the `/organization` prefix; there is no `/api/v1` prefix.

| Frontend screen / action | Method and path | Request contract | Response |
|---|---|---|---|
| Departments `/admin/departments` | GET `/departments` | q, active, limit, offset | Department page |
| Selected department details | GET `/departments/{id}` | Persisted department ID | Department |
| Create department | POST `/departments` | name, description (nullable), reason | Department, 201 |
| Update metadata | PATCH `/departments/{id}` | Changed name/description, expected_revision, reason | Department |
| Soft deactivate/reactivate | POST `/departments/{id}/deactivate` or `/reactivate` | expected_revision, reason | Department |
| Department assignment history | GET `/departments/{id}/assignments` | limit, offset; backend also supports optional active | Assignment page, server-scoped |
| Employees `/admin/employees` | GET `/employees` | q, active, home_department_id, limit, offset | Employee page |
| Selected employee details | GET `/employees/{id}` | Persisted user ID | Employee |
| Create identity | POST `/employees` | name, email, home_department_id, reason | Inactive canonical EMPLOYEE, 201, requires_trusted_onboarding=true |
| Update profile | PATCH `/employees/{id}` | Changed name/email/home_department_id, expected_revision, reason | Employee |
| Canonical role | POST `/employees/{id}/role` | organization_role, expected_revision, reason | Employee |
| Deactivate/reactivate account | POST `/employees/{id}/deactivate` or `/reactivate` | expected_revision, reason | Employee |
| Employee assignment history | GET `/employees/{id}/assignments` | limit, offset; backend also supports optional active | Assignment page, server-scoped |
| Assignments `/admin/assignments` | GET `/assignments` | active, user_id, department_id, limit, offset | Assignment page; Super Admin only |
| Create explicit assignment from employee details | POST `/assignments` | user_id, department_id, target user's expected_revision, reason | Assignment, 201 |
| Revoke assignment | POST `/assignments/{id}/revoke` | Target user's expected_revision from assignment response, reason | Assignment with revocation history |

Pages are exactly `{items,total,limit,offset}`. Backend limits are 1–100 rows and
offset 0–100000; UI choices are 20/50/100 rows, with bounded previous/next controls.
History and department lookup use 20-row pages. Search is sent to the backend,
never used to broaden client authority. Assignment search uses only its supported
user/department ID filters; no unsupported q or role query is invented.

Department fields: id, name, description, active, revision. Employee fields: id,
name, email, organization_role (nullable), home_department_id, active, revision;
requires_trusted_onboarding is exposed only on creation. Assignment fields: id,
user_id, department_id, assigned_at/by, revoked_at/by, revision. Revisions are
opaque 64-character fingerprints, not permissions or browser-editable form inputs.

## Screens and role presentation

All three screens reuse the existing admin shell. Lists include loading, empty,
error and success states, server counts, search/filter controls and pagination.
Department/employee row buttons load their detail and scoped assignment-history
panels from their actual detail endpoints. IDs are shown explicitly and can be
used as filter/reference values; the department picker additionally searches
active departments by name and supports pagination without loading all records.

Only exact `/auth/me.organization_role` values determine presentation. Super Admin
sees organization departments, employee identities and assignment history, plus
mutation controls. Department Admin sees assigned departments and departmental
employees as read-only screens, with only server-returned rows/history. Employees,
null and unrecognized roles get no organization navigation. The assignment route
has an additional Super-Admin presentation guard. Legacy role is not consulted.
Both admin roles retain their employee workspace and personal access requests.
The prior disabled Users placeholder is replaced by the supported employee screen.
Existing dashboards, resource/approval functionality and other unfinished links
are preserved.

Home department is labeled as membership, separately from explicit department-
admin assignment history. No home department, ownership, selected filter or cached
assignment supplies authority. Multiple admin rows per department and multiple
department rows per admin are shown without deduplication or inference. Revoked
rows retain assignment/revocation timestamps and actors. Department Admin sees no
assignment-management buttons or global assignment-list request.

## Mutation and concurrency behavior

Every mutation requires a reason and an explicit review/confirmation step,
including soft deactivation, reactivation, role changes and assignment revocation.
The form builds only allowlisted fields. Profile updates omit unchanged fields;
blank department description is explicitly null. Role changes use only the three
canonical values. Assignment creation is opened from a reviewed canonical
DEPARTMENT_ADMIN employee record and uses its identity revision. It never copies
the home department into the administrative assignment; department selection is
explicit. Self-assignment controls are withheld, and the backend still rechecks.

The displayed record's revision is captured when editing starts. Confirmation
sends that same expected_revision; no silent latest-revision fetch occurs before
the write. Double confirmation is prevented while the request is pending. Success
is shown only after a successful backend mutation response. Lists, selected details
and assignment history are then fetched again. The confirmation is closed on
failure, old rows/details are removed, and the operator must reload and review a
new command. No mutation, including a conflict, is automatically retried.

STALE_REVISION explains that current data must be reloaded and reviewed. Duplicate
normalized department names, duplicate identities/assignments, live department
references, already revoked assignments, last-Super-Admin protection, required
trusted onboarding, self-scope change and identity invariants get bounded messages.
Changing away from Department Admin includes an explicit instruction to revoke
active assignments first; the frontend does not claim to enforce the backend's
transactional rule. Unknown errors do not reveal raw exception or response data.
Network failures explain that a submitted change might already have committed,
requiring inspection before retry. A confirmed write followed by refresh failure
retains the confirmation and separately reports the read error.

On a read or mutation 403/404, prior rows/details are removed and the denial is
authoritative. Reload revalidates current backend scope. Focus/visibility changes
refresh displayed data when no edit is active. While editing, existing Unit 8
session revalidation and backend mutation authorization remain mandatory; reviewed
revisions are not replaced in the background. Out-of-order reads are ignored.
The existing client's protected 401 event clears organization state and returns
the application through Unit 8's session-ended/sign-in flow. No authority or
identity record is persisted in browser storage.

## Lifecycle and security limits

Creating an employee creates an inactive identity only. The success message says
trusted onboarding is required and sign-in is not ready. Later detail responses
do not reveal MFA/onboarding completion; inactive status is not labeled as proof
of a specific MFA state. Reactivation can return TRUSTED_ACCOUNT_SETUP_REQUIRED.
No onboarding, password delivery, enrollment authorizer or reset flow is invented.
Identity and assignment changes can invalidate target sessions and existing
generation-bound recovery inventory under unchanged backend rules. This screen
does not issue replacement credentials or recovery codes.

No credentials, hashes, MFA secrets/codes, session IDs or security generations are
rendered. Components select known display fields rather than dumping API records.
No hard deletion, role fallback, grant creation or sensitive-data elevation is
implemented. Backend Units 3/4/7 remain authoritative, including department scope,
last-admin protection, self-assignment, role eligibility and explicit revocation
before demotion. No new backend contract blocker was found for these screens.
The existing Unit 8 trusted-onboarding and reviewed HTTPS/CORS/Origin deployment
requirements remain; no live browser/backend deployment is tested in this unit.

## Exact Unit 9 file inventory

Updated:

- `frontend/src/routes/AppRoutes.tsx` — three organization routes and assignment guard.
- `frontend/src/components/layout/Sidebar.tsx` — enabled role-specific organization links.

Added:

- `frontend/src/types/organization.ts` — exact response/page/command/editor types.
- `frontend/src/api/organization.ts` — supported queries and mutation endpoints.
- `frontend/src/pages/admin/organizationController.ts` — reviewed commands, revisions and asynchronous state.
- `frontend/src/pages/admin/OrganizationPage.tsx` — lists, detail/history panels, picker and confirmed forms.
- `frontend/src/pages/admin/OrganizationPage.css` — scoped management styles using existing shell colors.
- `frontend/tests/organization.test.mjs` — isolated mocked transport and rendered-component regressions.
- `frontend/ORGANIZATION_MANAGEMENT.md` — inspected contract and implementation report.

## Verification

From `frontend`, run the unchanged test launcher and installed tools:

```powershell
npm test
npm run build
node node_modules/eslint/bin/eslint.js src/api/organization.ts src/types/organization.ts src/pages/admin/organizationController.ts src/pages/admin/OrganizationPage.tsx src/routes/AppRoutes.tsx src/components/layout/Sidebar.tsx
```

From the repository root: `git diff --check`.

Tests use fictional identities and a mocked Axios adapter, with real network
transport rejected. They exercise the controller used by the UI, exact mutation
payloads/paths, cookie/CSRF integration, all role presentations, restricted reads,
confirmation, double-submit protection, history, conflict/denial/session paths and
field allowlists. React server rendering verifies control visibility and content;
these are not interactive browser or real PostgreSQL/backend authorization tests.
All 33 prior Unit 8 tests remain unchanged.

No backend file, migration or database state is changed. No database command,
backfill, dependency installation, lockfile edit or backend process is run.

Final verification: complete suite 76/76 passed (33 unchanged Unit 8 tests plus
43 new Unit 9 tests); production TypeScript/Vite build passed; targeted ESLint
passed for all six new/updated TypeScript modules; `git diff --check` passed with
line-ending notices only. An initial new control-character validation regex was
replaced with character-code validation to satisfy ESLint; no unrelated failure
or application fix was introduced.

The pre-edit baseline contained 197 Git-visible files, including all existing
modified and untracked work. Hash comparison confirms two targeted frontend
updates, seven frontend additions, 195 existing files unchanged and none removed.
Every backend file, the existing authentication client/provider/controller and
tests, test loader, package manifest and lockfile are byte-for-byte preserved.
The requested build regenerates ignored frontend build artifacts/TypeScript
metadata only. No migration, database command or ordinary database access occurs.
