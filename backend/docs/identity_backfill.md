# Unit 2: atomic identities and reviewed backfill

Unit 10B prepares NOT NULL canonical identity validation in revision
0010_phase2_identity_validation, after 0009_phase2_org_management. Backfill must
precede those constraints. The utility's memory-only target restrictions and
trusted approval requirements are unchanged; there is no production PostgreSQL
execution adapter. See [phase2_unit10b.md](phase2_unit10b.md) for rollout ordering.

This unit adds internal services, not authorization. There are no new public APIs,
MFA credentials, authentication sessions, migrations, or changes to data access.
The caller must establish authorization independently. Unit 3 is not implemented.

## Identity transaction contract

Use the existing SQLAlchemy `Session` and an explicit outer transaction:

```python
with session.begin():
    change_organization_role(
        session, user_id, OrganizationRole.EMPLOYEE,
        expected_revision=reviewed_revision,
        evidence=IdentityEvidence(actor_id, "Approved organizational change"),
    )
```

Obtain `reviewed_revision` using `read_identity_state()` before the proposed change
is reviewed. Primitives require a clean session (no pending new/dirty/deleted ORM
objects), flush their mutation and audit together, and never commit. Do not catch
errors inside the outer transaction and then commit earlier operations. Audit
flush failures invalidate the transaction; the outer context rolls everything back.

The primitives serialize cooperating identity writers with a same-value user-row
UPDATE, then re-read and compare the reviewed identity revision. PostgreSQL takes
a row write lock; SQLite takes its database write lock. Stale snapshots/lock errors
must be retried only after refreshing and reviewing state. Revisions cover canonical
and legacy roles, home department, active state, assignment history, and identity
audit IDs. Audit IDs detect a role changed away and back (ABA). No schema version
column or second transaction framework is introduced. Direct SQL writers bypassing
this protocol are outside its guarantees and must not run concurrently.

Role changes away from DEPARTMENT_ADMIN require explicit assignment revocations
first. Repeated assignment creation/revocation with a fresh matching revision is a
no-op. No legacy role, owner, home department, or existing grant infers authority.

Identity audit events contain actor/target IDs, previous/new values, department,
UTC time, reason, and allowlisted approval identifiers. No model dump, password
hash, credential, session token, or secret is recorded. Legacy audit/detection
helpers are deliberately not invoked because they commit or suppress errors.

## Manifest schema

`IdentityBackfillManifest` is strict: unknown fields, invalid roles, duplicate JSON keys, duplicate users,
duplicate departments, duplicate revocations, missing approval fields and operator/
reviewer identity collisions are rejected. Both directory IDs and database user IDs
must differ between operator and reviewer. Every existing user, including inactive
accounts, must appear exactly once. Initial Super Admin, operator and reviewer must
be active existing users. There is no implicit ADMIN promotion.

`department_ids` is the complete desired active assignment set for that user.
Removing an existing assignment also requires its exact ID in
`revoke_assignment_ids`; removal is never inferred silently. Each mapping includes
the exact legacy role, canonical role and revision observed during review.

The digest is SHA-256 over the validated document serialized as sorted compact JSON.
It covers initial Super Admin selection, every mapping, operator, reviewer, reason,
manifest ID/version and approval reference. Changing any of these requires new review.

### Fictional example — not executable against real data

Every identifier and reference below is fictional. The zero revisions are
placeholders; they will not match an actual reviewed database state. This example
does not select or promote any actual GNOSIS user.

```json
{
  "schema_version": 1,
  "manifest_id": "FICTIONAL-EXAMPLE-ONLY",
  "manifest_version": 1,
  "initial_super_admin_user_id": "FICTIONAL-USER-SUPER",
  "operator": {
    "operator_id": "FICTIONAL-DIRECTORY-OPERATOR",
    "user_id": "FICTIONAL-USER-OPERATOR"
  },
  "reviewer": {
    "reviewer_id": "FICTIONAL-DIRECTORY-REVIEWER",
    "user_id": "FICTIONAL-USER-SUPER"
  },
  "approval_reference": "FICTIONAL-APPROVAL-NOT-REAL",
  "reason": "Fictional schema illustration only",
  "users": [
    {
      "user_id": "FICTIONAL-USER-OPERATOR",
      "expected_legacy_role": "ADMIN",
      "expected_organization_role": null,
      "expected_revision": "0000000000000000000000000000000000000000000000000000000000000000",
      "organization_role": "EMPLOYEE",
      "department_ids": [],
      "revoke_assignment_ids": []
    },
    {
      "user_id": "FICTIONAL-USER-SUPER",
      "expected_legacy_role": "EMPLOYEE",
      "expected_organization_role": null,
      "expected_revision": "0000000000000000000000000000000000000000000000000000000000000000",
      "organization_role": "SUPER_ADMIN",
      "department_ids": [],
      "revoke_assignment_ids": []
    },
    {
      "user_id": "FICTIONAL-USER-DEPT",
      "expected_legacy_role": "EMPLOYEE",
      "expected_organization_role": null,
      "expected_revision": "0000000000000000000000000000000000000000000000000000000000000000",
      "organization_role": "DEPARTMENT_ADMIN",
      "department_ids": ["FICTIONAL-DEPARTMENT-A", "FICTIONAL-DEPARTMENT-B"],
      "revoke_assignment_ids": []
    }
  ]
}
```

## Dry-run and execution gates

The command `python -B backend/scripts/migrate_identity_roles.py --manifest <path>`
defaults to **offline schema validation only**. The manifest must be inside the
workspace. It prints a digest and explicitly reports that database coverage and
execution approval have not been verified. It never reads DATABASE_URL, opens the
ordinary application database, creates a schema, or applies migration 0007.

For a prepared in-memory fixture, internal `run_backfill(engine, manifest,
environment_id=...)` performs a database-aware dry-run by default. It validates the
entire user inventory, departments and reviewed baseline without mutation or locks.

Execution requires all of:

1. An explicitly supplied, already prepared `sqlite:///:memory:` engine and named
   disposable environment. File-backed, attached file databases, URI variants and
   every network/PostgreSQL target are rejected. No engine/schema is auto-created.
2. `execute=True` (or `--execute` in an injected trusted CLI host).
3. Exact confirmation `APPLY:<manifest_sha256>` supplied separately from the manifest.
4. An injected trusted review verifier. It must authenticate an independent approval
   outside the operator-controlled document and return `VerifiedReview` bound to the
   manifest digest, reviewer IDs, approval reference, approval record ID, environment,
   exact database URL, actual prepared engine instance, disposable designation and
   unexpired approval validity. The verifier receives `(manifest_digest,
   environment_id, engine)` and must resolve that instance through its trusted
   environment registry rather than accepting the operator's environment label.

Reviewer text in JSON is **not** authenticated review. The repository has no trusted
review integration, and this unit does not invent one. The ordinary CLI cannot
execute: it has neither an injected verifier nor a prepared disposable engine.
Tests supply a clearly fictional verifier only for their in-memory fixtures. This
test stub must never be installed as an operational approval verifier. Even a
trusted verifier cannot enable PostgreSQL execution in this unit.

The future integration must prevent an operator from modifying or issuing their own
review record. Approval must bind the exact initial Super Admin selection; a manifest
hash or different reviewer name alone does not establish independence. Directory
alias resolution and the real human approval procedure remain external prerequisites.

## Atomicity, interruption and reruns

Execution locks mapped user rows in stable order, validates all users and departments,
then performs the whole manifest in one SQLAlchemy transaction. Role mutations,
assignment creation/revocation, their audit events, and an
`IDENTITY_BACKFILL_COMPLETED` receipt commit together. A middle-operation, audit,
receipt or interruption failure rolls the entire transaction back. Rerun the same
reviewed manifest after interruption; there are no partially committed chunks.

A committed rerun checks the exact manifest ID/version/digest and final identity
revisions. It returns the original receipt without duplicate audits or assignments.
Reusing an ID/version with changed content, or restoring state after later identity
changes, is rejected. New mappings require a new reviewed manifest. Caller must
quiesce external user/department creation during execution; this unit does not add
application maintenance controls. It does not repair unreviewed partial state.

Existing user IDs, legacy roles, home departments, passwords, owners, grants, requests
and audit evidence are preserved. There is no migration or destructive rollback
command. Model/identity test writes occur only inside guarded in-memory fixtures.

## Verification

Use the unchanged isolated launcher:

```text
.\.venv\Scripts\python.exe -u -B backend/scripts/run_phase1_tests.py backend/tests/test_identity_service.py backend/tests/test_identity_backfill.py -q
.\.venv\Scripts\python.exe -u -B backend/scripts/run_phase1_tests.py backend/tests -q
```

Real PostgreSQL concurrency and deployment approval integration remain unverified;
they require separate review and an explicitly approved disposable environment.
