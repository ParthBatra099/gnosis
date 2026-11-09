# Isolated local evaluation authentication

**DEMO MODE — Password-only authentication for fictional local accounts. MFA is not being demonstrated.**

This is operator-controlled local academic evaluation, not production authentication,
independent reviewer approval, or protection from the Windows administrator. The
operator can alter source, manifests, database markers and audit records. Do not
expose this service via LAN, tunnels, reverse proxies, port forwarding or hosting.
Normal `app.main:app` is unchanged and still requires persisted, verified MFA sessions.
No environment variable enables this factory. There is no MFA fallback.

## External prerequisites (not performed by this change)

An operator must separately approve and prepare an empty, disposable local PostgreSQL
database, migrate it through head `0012`, and supply a locally trusted HTTPS certificate
and private key. No database was provisioned or migrated during implementation.
The approved database must have the exact database comment
`GNOSIS_LOCAL_DISPOSABLE_DEMO:<instance UUID>`, set during separately approved preparation.
The launcher never creates this marker or infers disposability from a database name.
Record the actual database OID, role, host, port and schema in a reviewed target file.
Do not select an ordinary project database. Use a dedicated least-privilege database role.

Example **fictional** target (values must be replaced with separately verified values):

```json
{"host":"127.0.0.1","port":5432,"database":"fictional_demo",
 "schema_name":"public","database_role":"fictional_demo","database_oid":12345,
 "instance_id":"00000000-0000-0000-0000-000000000099","disposable":true}
```

Target checks compare configured URL components, current database/user/schema, database
OID, server port, exact instance marker and sole migration revision. Only loopback
targets and public schema are supported. The PostgreSQL checks have isolated contract
tests, not a live PostgreSQL rehearsal. A matching marker is an operator assertion,
not cryptographic proof that the database is non-production.

Live verification repeats inside each authentication transaction, on that operation's
SQLAlchemy connection. This includes CSRF bootstrap, rate admission, login, failure
audit, profile validation and session inventory/revocation. Any missing, different or
unverifiable observed target identity permanently invalidates that process's demo run
and clears its registry. Later requests fail closed without attempting recovery.
An explicit process restart and successful target verification are required.

**Restore limitation:** a restore preserving every observed identity value (including
database OID, instance marker, schema name, role and migration revision) cannot be
detected automatically. The operator must stop the demo before restoring or replacing
its database, explicitly verify the database, and only then restart. This is an
operator-controlled local evaluation environment, not production-grade restore protection.

## Manifest and identities

Use `backend/demo/identities.example.json` as a fictional example. Review it before use;
all identifiers are fictional. Version, user UUIDs, canonical roles, home departments,
initial Super Admin and fictional flag are explicit. Only `demo-*@example.com` addresses
are accepted. Extra fields (including passwords) are rejected. Legacy role is stored as
`EMPLOYEE` provenance, never consulted to determine authority. Exactly one initial
Super Admin is required. Names and emails must describe fictional people only; code
cannot prove the truth of the operator's fictional declaration.

Bootstrap creates active identities but **no** MFA credentials, challenges, recovery
codes, authenticated sessions, assignments, grants, resources or business records.
Create explicit department-admin assignments after login through the existing organization
API, attributed to the real logged-in demo Super Admin. Department Admin alone does not
give department scope. This avoids fabricating an authenticated bootstrap user actor.

## Operator workflow

Run from the repository root; no `.env` or normal deployment profile is selected.
Supply all paths explicitly. Passwords are prompted via `getpass`, never command-line
arguments, files or logs. The database password and each fictional user's password are
per-run operator inputs; user passwords require 12–1024 characters and confirmation.
The fresh-process launcher installs an explicit private `app.core.config` adapter before
any business/database import. It does not import or initialize normal `Settings`, read
`.env`, or consume normal configuration environment values. It refuses to replace an
already initialized application. Normal startup still loads its original configuration.

```powershell
# Default: validate target and empty identity/audit/department state; no identity writes.
.\.venv\Scripts\python.exe -B backend/scripts/run_local_demo.py bootstrap --local-demo --ack-password-only-demo --target <target.json> --manifest <manifest.json> --operator <operator-identifier>

# Apply requires a separate exact instance confirmation.
.\.venv\Scripts\python.exe -B backend/scripts/run_local_demo.py bootstrap --local-demo --ack-password-only-demo --target <target.json> --manifest <manifest.json> --operator <operator-identifier> --apply-confirmation APPLY:<instance-UUID>

# Read-only reconciliation; never repairs or overwrites existing identities.
.\.venv\Scripts\python.exe -B backend/scripts/run_local_demo.py verify-existing --local-demo --ack-password-only-demo --target <target.json> --manifest <manifest.json>

.\.venv\Scripts\python.exe -B backend/scripts/run_local_demo.py serve --local-demo --ack-password-only-demo --target <target.json> --manifest <manifest.json> --origin https://localhost:5173 --tls-cert <certificate.pem> --tls-key <private-key.pem>
```

The launcher uses `127.0.0.1:8443`, one worker, no reload, no proxy-header trust and
no access logging. It generates independent per-run configuration, CSRF and rate-limit
keys. No normal JWT, encryption or transport secrets are reused. Public/non-loopback
peers and hosts, HTTP and forwarded headers are rejected by application middleware too.
No frontend is implemented here. An HTTPS frontend must use credentials, the demo cookie
namespace and `/auth/csrf`, and explicitly require `LOCAL_DEMO_PASSWORD_ONLY` before
accepting the password-only response. The normal AuthController deliberately expects
MFA challenges and is incompatible. Use a separate browser profile for demo evaluation.

## Atomic provenance and failures

Bootstrap holds a PostgreSQL advisory transaction lock, checks empty state, inserts
departments and users, and inserts one deterministic `LOCAL_DEMO_BOOTSTRAPPED` audit
receipt in the same SQLAlchemy transaction. Password hashing uses existing Argon2.
The receipt has a null application actor, explicit external operator identifier,
manifest version/hash, target hash and instance UUID. No authenticated actor is invented.
Any insert/audit failure rolls everything back. No existing state is updated or deleted.
An already populated target always rejects bootstrap; `verify-existing` is the
idempotent read-only reconciliation operation. After uncertain commit acknowledgement,
use verify-existing, not blind apply. Conflicts/drift require investigation, never reset.
Password prompts hold no database transaction. Apply rechecks the target and empty state
under a fresh advisory transaction lock after all passwords have been entered.

At startup, target/receipt/identity state must agree. At every authentication request,
the exact receipt and manifest identity must still agree, active canonical identity is
checked and the existing identity lock/generation service is used. Missing, duplicated,
modified or mismatched receipts deny access. Post-bootstrap users are ineligible.
Name, home department, email or canonical-role drift denies new demo login until a
separately reviewed future procedure exists; the utility never silently rewrites receipts.

## Session/audit contract

Demo sessions are opaque random capabilities in one process, with run ID, generation,
identity revision, creation/activity times, 30-minute absolute and 15-minute idle expiry,
and revocation state. They are explicitly `LOCAL_DEMO_PASSWORD_ONLY`, with no MFA time.
Every protected request checks current DB identity, receipt, generation and identity
revision. Restart loses the registry and keys. Cookie names are
`__Host-gnosis_demo_session` / `__Host-gnosis_demo_csrf`; both Secure, HttpOnly,
SameSite=Strict and Path=/. CSRF binds exact HTTPS origin and session, expires after
600 seconds and requires cookie/header equality. Bearer tokens are not accepted.
Both cookie namespaces and validators reject the other realm's sessions.

Login account/source admission counters commit before password checking using existing
atomic rate-limit primitives and private per-run HMAC keys. Restart resets the demo
rate-limit namespace, a local-demo limitation. Successful `DEMO_SESSION_CREATED` audit
must commit before registry publication/cookies. Failed login audits contain no submitted
credentials. Revocation checks current authority/session, commits `DEMO_SESSION_REVOKED`
before registry mutation, and reports no success on audit failure. Persisted revocation
audit is also checked on validation, covering ambiguous commit acknowledgement.
Audit references are SHA-256 session fingerprints, never raw capabilities.

Activity/idle extensions are queued and published only after database commit; failed
commits leave both unchanged. Ordered per-user locks serialize login, validation and
revocation through commit/publication, with a five-second lock-acquisition limit. The
global registry lock covers memory snapshots/publication only, never hashing or SQL.
Existing DB identity locks still serialize with normal identity mutations. Requests
already admitted to business handlers are not retroactively cancelled by revocation.

The supported launcher limits its connection pool to five connections, no overflow,
five-second pool/connect waits, five-second statements, three-second database locks and
60-second idle transactions. Target verification sets transaction-local statement/lock
timeouts as well. Network/OS stalls are not a universal hard deadline. These PostgreSQL
settings have not been exercised against a live database in this implementation task.

At most 20 active sessions and 100 recent session metadata entries are retained per
manifest user; oldest expired/revoked metadata is evicted as necessary. Audit evidence
is never deleted. Revocation uses deterministic per-session audit IDs and primary-key
lookups rather than scanning accumulated revocation history. A committed revocation
whose acknowledgement was lost remains a durable deny even before memory publication.

Own session list/revoke/logout/logout-all are supported for every canonical role;
organization session list/revoke retains Super Admin-only central identity authority,
even for self-targeting through that route. Existing authorization and business-data
policies are unchanged. No AI Security Investigator router is installed in demo mode.

Normal MFA workflows and account lifecycle policies remain intact. Reactivation still
requires a real active MFA credential, and last-admin protections retain that condition;
these operations may be unavailable in password-only demo. This is not an MFA lifecycle
demonstration. No live browser/TLS or PostgreSQL concurrency claim follows from SQLite tests.

Run regressions only with the unchanged isolated launcher:

```powershell
.\.venv\Scripts\python.exe -u -B backend/scripts/run_phase1_tests.py backend/tests/test_local_demo.py -q
.\.venv\Scripts\python.exe -u -B backend/scripts/run_phase1_tests.py backend/tests -q
```
