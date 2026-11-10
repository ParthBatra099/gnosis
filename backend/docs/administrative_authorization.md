# Phase 2 Unit 4: administrative consumer migration

This document describes the Unit 4 integration. The Unit 3 action matrix remains
the organizational policy definition; Unit 3's document describes its earlier
standalone delivery. No identity mapping, migration, authentication or business-data
policy is introduced here.

## Endpoint-to-action matrix

All routes still resolve identity through the existing `get_current_user`
dependency. Only its database user ID supplies the actor. JWT roles, frontend
department claims, home department, resource ownership and incidental relationships
are never authority inputs.

| Route / consumer | Unit 3 action and authoritative scope |
|---|---|
| GET `/access/requests/pending-approvals` | `DEPARTMENT_GRANT_ADMINISTER`, request resource's department |
| POST `/access/requests/{id}/approve` | `ACCESS_REQUEST_APPROVE`, `AccessRequestScope(id)` resolves requester/resource/department and forbids self-approval |
| POST `/access/requests/{id}/reject` | `ACCESS_REQUEST_REJECT`, database-resolved request scope |
| GET `/access/grants/owned` | `DEPARTMENT_GRANT_ADMINISTER`, grant resource's department; historical URL retained |
| POST `/access/grants/{id}/revoke` | `DEPARTMENT_GRANT_ADMINISTER`, locked grant resource's department |
| GET `/monitoring/audit-logs` | `DEPARTMENT_SECURITY_MONITOR`, audit resource's department; `ORGANIZATION_SECURITY_MONITOR` for global scope |
| GET `/monitoring/security-events` | Same monitoring actions, both event resource and source-audit resource departments |
| GET `/console/incidents` and `/console/incidents/{id}` | `DEPARTMENT_INCIDENT_INVESTIGATE`, primary resource and every linked event/source-audit department; `ORGANIZATION_SECURITY_MONITOR` for global reads |
| POST `/console/incidents` | `DEPARTMENT_INCIDENT_INVESTIGATE`, actual primary resource and every prospective evidence department; `ORGANIZATION_ADMINISTER` for a NULL resource scope |
| PATCH `/console/incidents/{id}` | Same investigative actions, locked existing incident and all linked evidence |
| POST `/console/incidents/{id}/events` | Same investigative actions, existing and prospective linked evidence |
| Assignee validation on create/update | Proposed assignee must independently pass investigative authority for the complete incident/evidence scope |
| GET `/console/dashboard/summary` | Incident count uses incident scope; critical-event count uses monitoring scope; pending count uses grant-administration scope |
| AI audit/security/activity/recent tools | Exactly the shared monitoring queries above, then allowlisted filters and a 1–100 limit |
| AI incident/detail/evidence/recent tools | Exactly the shared incident and evidence queries above |

Organization-only operations require Super Admin through Unit 3. Department Admin
requires explicit active assignments; multiple assignments compose departmental
visibility. All department checks, including Super Admin's, remain in Unit 3.
No role/assignment branches are reimplemented in the consumer integration.

## Query boundary and compatibility

`services/administrative_access.py` composes SQL predicates from fresh Unit 3
decisions. Resource IDs are selected from actual `Resource.department_id`; no
frontend department value can replace it. SQL WHERE restrictions precede ordering,
limits and aggregation. No decisions are cached across requests.

An audit without a resolvable resource is organization-only. A security event with
no resource, or with a source audit whose resource is outside scope/unresolved,
is hidden from Department Admin. An incident is hidden in its entirety if its
primary resource or any linked evidence is outside scope/unresolved. This prevents
its title, count and evidence identifiers from leaking through incident lists or AI
summaries. NULL predicates are explicitly false, including beneath NOT EXISTS.
Super Admin's global monitoring scope includes unscoped legacy evidence. Mutations
still reject missing evidence records rather than silently accepting broken links.

Administrative lists return authorized rows, possibly an empty list; dashboard
counts may be zero. Unauthorized incident detail/update/attach targets return 404.
Other denied administrative mutations return 403 with the Unit 3 reason; missing
resolved targets return 404. No exception or policy-service failure falls back to
owner/actor/reporter/assignee/legacy-role access.

Users without reviewed canonical roles/assignments lose administrative access.
Deployment therefore depends on the separately reviewed Unit 1 storage and Unit 2
identity mapping process. Unit 4 does not inspect live mappings or execute them.

The `/grants/owned` URL remains compatible, but now means grants in administered
departments. Employees no longer get administrative audit/security visibility even
for their own actions. Reporter and assignee fields remain evidence/workflow
metadata. Existing ineligible assignees are preserved and gain no access; they do
not prevent an authorized investigator from attaching evidence. New assignments
must meet current scoped investigative authority. Status progression, required
resolution notes, timestamps, duplicate-link handling and automatic detection
remain intact.

## Transactions and locks

Authentication normally autobegins a read session. Each sensitive handler calls
`mutation_transaction(source_session)`, which opens an ordinary SQLAlchemy Session
on the **same existing bind**, then an explicit `with db.begin()` transaction.
There is no new engine, database URL, transaction framework, or rollback of the
authentication/caller session. Response models are materialized before this
operation commits and closes. Callers retaining ORM instances in another Session
must refresh them to observe committed changes.

Request approval/rejection delegates to Unit 3 transaction revalidation, which
locks the actor through Unit 2, locks the request/resource and re-resolves scope.
The handler reloads the locked request before lifecycle checks. Grant operations
revalidate, lock the actual resource and grant, reload the grant and revalidate
its current resource department again. Incident operations revalidate and lock
the primary resource, lock/reload the incident, then lock every linked security
event/source audit and its actual resource and revalidate each department.
Evidence additions share the incident row lock. Proposed assignees also receive
Unit 2 identity locks and current Unit 3 checks before any mutation is staged.

Locks remain held through mutation and audit commit. Unit 2 role/assignment writers
cooperate using the same actor user-row lock. Direct SQL identity writers are
outside that protocol. Multi-actor/cross-resource lock contention can cause database
deadlock/serialization errors; these propagate, roll back and require a fresh
request rather than returning an ALLOW or retrying stale state automatically.

`append_audit` adds and flushes an AuditEvent without committing or suppressing
errors. Approval/grant changes, rejection, revocation, incident creation/update,
and evidence attachment commit with that event. Audit failure rolls back all of
the operation, including links and grants. Evidence-attachment audits record an
event count rather than disclosing cross-department event IDs via a primary-resource
audit. Existing deterministic detection runs **after** the atomic commit because
the detector owns internal commits. Detection remains best effort and does not
undo the durable administrative audit or mutation.

## Intentionally retained paths and exclusions

- Personal `/access/requests`, `/requests/me`, `/grants/me` and the high-level
  resource metadata discovery catalog remain ordinary employee functionality.
- `security/access_decision.py`, `evaluate_access()`, resource/field permissions,
  grants' business-data semantics and the personal assistant are unchanged.
  In particular the existing ownership-based data-access behavior is still
  present pending the separately approved Option B change. Organizational
  authority never calls or overrides that data-access engine.
- The personal assistant's legacy-role profile string is display information,
  not an administrative authorization branch.
- Detection's reporter comparison groups automatic incidents; it does not give
  the reporter authority. System-generated evidence/incident escalation remains
  unchanged. No other human administrative router or background consumer was
  found by the backend role/ownership/helper search.
- Unit 1 models/migration, Unit 2 identity services/backfill and Unit 3 policy
  service/tests remain unchanged. No backfill, project migration or live database
  command is executed. Frontend and authentication code are unchanged.

## Authentication assurance and remaining limitations

The existing JWT authentication dependency supplies identity only. Password-only
tokens are **not MFA verified**, have no new session ID requirement and remain
subject to their existing revocation limitations. No synthetic trusted-principal
context, session record, MFA flag or recovery credential is invented. Units 5/6
must replace the authentication boundary with server-tracked, revocable,
MFA-verified sessions before claiming that assurance.

Unit 3 denies corrupt canonical roles explicitly. The unchanged authentication
dependency ORM-loads User before policy; corrupt Enum storage can therefore raise
a server error before Unit 3 is reached. It cannot grant authority or commit the
administrative mutation. Authentication error normalization remains deferred.

Visibility currently enumerates departments and evaluates Unit 3 per department;
this favors a single policy source over a second hand-written role SQL policy.
Large organizations may need a reviewed batch policy interface later. Existing
normal API list endpoints remain unpaginated; AI limits remain bounded.

PostgreSQL runtime concurrency is not proved by in-memory SQLite. Tests exercise
deterministic identity/scope interleavings and compile the actual executed locking
statements for PostgreSQL without opening a PostgreSQL connection. A separately
approved disposable PostgreSQL concurrency run remains a deployment verification
item. No ordinary project database is used for any test.

## Verification

All tests use the unchanged `scripts/run_phase1_tests.py` launcher. It installs
engine and pre-DBAPI connection guards before application imports, replaces the
application URL with exact `sqlite:///:memory:`, and rejects file/network databases.

Commands (from the workspace root):

```powershell
.\.venv\Scripts\python.exe -u -B backend/scripts/run_phase1_tests.py backend/tests/test_test_isolation.py -q
.\.venv\Scripts\python.exe -u -B backend/scripts/run_phase1_tests.py backend/tests/test_administrative_consumers.py -q
.\.venv\Scripts\python.exe -u -B backend/scripts/run_phase1_tests.py backend/tests -q
git diff --check
```

Existing lifecycle fixtures now seed explicit test-only canonical roles and
department assignments. No ownership-to-role inference, application seed mapping
or backfill is added. Superseded reporter/self-actor visibility assertions now
assert denial; other expiry/lifecycle/detection/atomicity assertions remain.

The new boundary suite covers roles, missing/invalid canonical roles, legacy ADMIN,
owners/reporters/assignees denied, self-approval, forged department input, revoked
assignments, multiple assigned departments, cross-department and NULL evidence,
SQL-scoped counts, API/AI parity, strict audit rollback for every migrated mutation,
authority errors, and changes between preliminary checks and locked revalidation.

Final verification: 440 passed, with the same two pre-existing Starlette/Pydantic
deprecation warnings. The pre-edit baseline was 380 passed. Isolation checks alone
passed 7/7; the dedicated Unit 4 suite contributes 60 tests. The final full launcher
reported 425 guarded engines, 424 in-memory connections and 6 intentionally blocked
unsafe isolation probes. `git diff --check` passed. No build, installation,
PostgreSQL connection, live migration or backfill was executed.

The initial compatibility run exposed 39 failures from superseded owner/self-actor/
reporter authorization assumptions and fixtures without canonical assignments.
After explicit fixture updates, one stale ORM fixture assertion required a refresh
from the administrative transaction's committed state. No unrelated application
fix was added. Existing Unit 1–3 files and all files outside the 10 intentionally
edited consumer/regression files match the pre-edit SHA-256 baseline (153 files
unchanged); Unit 4 adds this document, the integration service and its test module.
