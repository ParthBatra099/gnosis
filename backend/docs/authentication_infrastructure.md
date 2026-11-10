# Phase 2 Unit 5 authentication foundation

Unit 5 adds internal storage and primitives only. It does not enable mandatory MFA,
change public login/JWT behavior, issue real-user sessions, or replace the existing
authentication dependency. Unit 6 supplies actual TOTP/recovery verification;
Unit 8 coordinates the frontend cutover. Existing legacy JWTs remain usable by
the existing dependency until that separately approved cutover. They are not
MFA-verified sessions and cannot validate through the new session primitive.

## Additive schema and migration

The verified repository chain is `0006_phase_4` → `0007_phase2_organization` →
`0008_phase2_authentication`. This describes files, not the live database state.
No live database was queried, no migration applied and no identity backfill run.

Migration 0008 creates six tables without altering existing user/business tables:

| Table | Purpose and principal constraints |
|---|---|
| `user_authentication_states` | One state per user, monotonic service-managed security generation, creation/update timestamps |
| `mfa_credentials` | AES-GCM ciphertext and key version, enrollment/activation/revocation metadata, last accepted TOTP step; one ACTIVE and one PENDING credential per user, retained REVOKED history |
| `authentication_challenges` | Random identifier, hash of a separate high-entropy secret, user, type/purpose, generation, expiry, failed attempts and terminal consumption/revocation timestamps |
| `authentication_sessions` | Opaque random session ID, user, unique consumed challenge, credential, generation, absolute/idle expiry, activity, TOTP verification and revocation evidence |
| `recovery_codes` | Strong encoded Argon2id hash only, user/generation, creation and single-use consumption timestamp |
| `authentication_rate_limits` | HMAC bucket key/category, bounded attempts, threshold, window length/start/expiry |

Every authentication foreign key uses RESTRICT. No cascading deletion of
credentials, sessions or authentication history is added. Check constraints enforce
allowlisted lifecycle values, valid timestamp ordering, nonnegative generations,
bounded counters, hash/ciphertext format minima and paired revocation metadata.
Unique indexes prevent concurrent duplicate active/pending MFA credentials;
unique challenge/session relationships prohibit issuing two sessions from one
challenge. A replacement pending credential may coexist with the old active one.
Unit 6 must atomically revoke the old credential before activating its replacement.

ORM models are registered through `app.models`. Relationships to User are
unidirectional, leaving the existing User fields and identity provenance intact.
Migration 0008 inserts no state, credentials, codes, sessions or enrollment flags.
An authentication state is initialized only when a trusted workflow requests it.

The downgrade refuses destructive removal unconditionally, consistent with 0007.
Rollback means reverting application integration while retaining the additive
schema and history. Any future archival/removal requires a separately reviewed
operation and verified backups, never a reset or automatic downgrade.

## Transaction, identity and audit contract

All mutation primitives require the existing SQLAlchemy Session and an explicit
caller-owned `with db.begin():` transaction, with pending ORM changes flushed.
They flush but never commit, roll back independently or suppress audit failures.
Exceptions must escape the outer transaction; do not catch a partially staged
authentication mutation and then commit it. Return newly issued capabilities only
after the caller's commit succeeds.

The shared `locked_state` helper first uses current scalar canonical identity
validation and then Unit 2's existing user-row identity lock. It locks/reloads
authentication state. Cooperating Unit 2 identity writers and authentication
writers therefore serialize on the same user row. Inactive, missing, NULL or
invalid canonical identities cannot create or validate authenticated sessions.
There is no legacy-role fallback, ownership authority or organization-role MFA
exception. All three canonical roles follow the same MFA-session contract.

State-changing security events append AuditEvent rows in the same transaction.
Events include target/actor IDs, bounded action names, generation changes,
allowlisted revocation causes and nonsensitive purpose/attempt metadata. Sessions
are referenced in audits by digest, not raw IDs/tokens. No secret, OTP, provisioning
URI, recovery code or bearer token is logged or accepted as arbitrary audit data.
The best-effort audit helper and committing detector are not used for these writes.

These internal services are not authorization. In particular, specifying an audit
actor for revocation/invalidation does not establish that actor's authority.
Unit 6 or a later administrative caller must separately authorize the operation.

## Restricted challenge API

`create_challenge(db, user_id, purpose, ...)` returns `ChallengeTicket(id, secret)`.
The secret has 256 bits of CSPRNG entropy; only its SHA-256 digest is persisted.
The identifier alone is insufficient to validate/consume a challenge. The secret
is omitted from object repr. This is a restricted capability, never a full session
or a token accepted by ordinary application endpoints.

Purposes are exactly MFA_ENROLLMENT, MFA_VERIFICATION, ACCOUNT_RECOVERY and
REPLACEMENT_ENROLLMENT. The first three have PASSWORD_VERIFIED prerequisite type;
replacement enrollment has RECOVERY_VERIFIED prerequisite type. Unit 6 must
establish those prerequisites through real verification before calling this
low-level storage primitive; the purpose/type fields themselves are not proof.

`validate_challenge` reads current user/state and validates user, secret, type,
purpose, generation, timestamps, consumption/revocation and failed-attempt budget.
`consume_challenge` combines the identity lock and a conditional UPDATE RETURNING;
only the first valid consumption can succeed. `record_challenge_failure` atomically
increments persisted failed verification attempts and writes its audit event.
Successful attempts do not increment this failed-attempt field. Shared rate limits
separately count all attempts. Exhaustion rejects subsequent verification.

Failed-attempt counters must be committed before returning the verification denial
to HTTP. Raising inside the counter transaction would undo the protective counter.
Do not put failure counters in a later transaction that might roll back because
an OTP/password was incorrect.

## Session API and trusted verification contract

`create_session(db, user_id, ticket, verifier=..., ...)` has no default production
verifier. Unit 6 must provide server-owned `SessionVerificationProvider` code.
It must perform real TOTP verification against the persisted credential and return
`TOTPVerification` bound to the exact user, challenge, current generation,
credential, verification timestamp and accepted time step. A dataclass, dictionary,
JWT MFA claim, password result or caller-supplied boolean is not authentication.
The provider must never be selected or deserialized from client/LLM input. Tests
use an explicitly test-only fake; no fake is shipped in application services.

The session service checks fresh bound evidence, active credential ownership and
activation, then atomically consumes the challenge, reserves a strictly newer TOTP
step and persists the session/audit. Unit 6 must not separately reserve the same
step before invoking this service. Enrollment activation must be flushed with its
own strict audit in the same outer transaction before session issuance. An account
recovery challenge is always rejected for full-session creation, even with an
object claiming TOTP verification. A recovery code alone cannot issue a session.
Enrollment/replacement purposes additionally require a credential enrolled no
earlier than their challenge, preventing reuse of the pre-existing credential as
proof of completing new enrollment.

Session IDs have 256 bits of CSPRNG entropy. No raw signed bearer token is stored.
`validate_session(db, subject_user_id, session_id, ...)` independently requires
persisted session/state, active valid canonical identity, matching subject and
generation, valid absolute/idle expiry, nonrevocation, persisted TOTP evidence,
active credential/replay state and a valid consumed verification challenge chain.
No `sub`, `sid` or MFA claim substitutes for those records. It returns an immutable
`SessionPrincipal` with `subject_user_id` and `authentication_context_id`, satisfying
Unit 3's structural trusted-principal contract. Constructing or retaining that
object is not proof: validation must occur anew for every request.

Read validation does not write. `touch=True` requires an explicit transaction,
takes the shared user lock, locks/reloads the session and extends idle expiry only
up to the immutable absolute expiry. The future authentication dependency must
validate signed transport first, then use persisted validation/touch under the
caller transaction and commit successfully before admitting the request.

`revoke_session` is idempotent. `invalidate_user_sessions` increments security
generation and revokes existing unrevoked sessions/unconsumed challenges together
with audit evidence. Generation-bound unused recovery codes become invalid too.
An existing active TOTP credential may verify afresh under the new generation;
credential replacement/revocation is a separate Unit 6 workflow. Password changes,
recovery and credential replacement must invoke generation invalidation in their
own atomic transactions. Existing Unit 2 identity operations are not rewritten.

## Recovery inventory primitives

`hash_recovery_code` uses the existing Argon2id dependency and disposable caller
input. `store_recovery_hash` only accepts a validated strong encoded hash, with
bounded verification costs; the schema has no plaintext code column. Unit 6 must
generate independent high-entropy codes and only reveal them through its approved
recovery-code delivery workflow. This unit generates no real-user codes.

`consume_recovery_code` verifies the candidate, checks user/generation and uses a
conditional single-use UPDATE under the same user lock, with an atomic audit. It
returns no full-session proof. Its low-level code ID is an internal inventory
selector; the public recovery API and safe inventory lookup do not exist yet.
Unit 6 must require password verification, a restricted recovery challenge,
constant/neutral failure responses and committed throttling before attempting it.

Required recovery transaction ordering: consume restricted recovery challenge and
code, invalidate prior security generation/sessions/challenges, then create a new
REPLACEMENT_ENROLLMENT challenge bound to the new generation. All share one outer
transaction and strict audit evidence. Replacement TOTP must then be verified and
activated before the normal session service can create full application access.

## Encryption and deployment keys

`mfa_encryption.py` uses PyCA cryptography's AES-256-GCM with a fresh random 96-bit
nonce, full authentication tag, and authenticated context binding domain version,
user ID, credential ID and key version. Stored binary material is nonce followed
by ciphertext/tag. Wrong keys, versions, tags or context fail closed. It supplies
encryption/decryption only, not TOTP generation, QR provisioning or verification.
See the [official AEAD documentation](https://cryptography.io/en/latest/hazmat/primitives/aead/).

Provision these through an approved managed secret delivery mechanism before
enabling Unit 6. No production KMS integration or automatic persistent fallback
key is implemented:

- `MFA_ENCRYPTION_KEYS`: secret JSON object mapping stable version names to base64
  encodings of independent 32-byte managed encryption keys.
- `MFA_ENCRYPTION_ACTIVE_KEY_VERSION`: version used for all new encryption.
- `AUTH_RATE_LIMIT_KEY`: a **separate** managed base64 32-byte HMAC key shared by
  every authentication worker; never reuse the JWT or MFA encryption key.

Settings use SecretStr for key material. Loading malformed/missing key rings,
duplicate versions or unknown active versions fails closed when the primitives
are used. Existing login remains unchanged and does not invoke them yet. Tests
generate disposable in-memory keys only; no `.env` or persistent fallback key is
created. Python cannot promise reliable zeroization of all secret memory copies.

For rotation, provision a new version to all workers while retaining decrypt-only
old versions, switch active version consistently, then re-encrypt each credential
with the same user/credential identity in an audited transaction. Preserve its
TOTP replay/lifecycle metadata. Verify migration and backup recovery before
retiring old keys. Never silently change key material behind an existing version.
The rotation workflow itself is deferred; the foundation supports versioned reads
and writes. Rotation of the rate-limit HMAC key changes bucket identities and
must be coordinated after active windows expire or through a separately reviewed
overlap strategy, never independently per worker.

## Shared rate limiting and policy

`record_attempt` uses a single database INSERT ON CONFLICT DO UPDATE RETURNING,
not read/increment/write in Python. PostgreSQL serializes conflicting bucket
writes across workers. The primitive also supports isolated SQLite tests. It uses
an HMAC-SHA-256 bucket of an allowlisted category plus normalized identifier.
Only account IDs/emails, challenge IDs or approved source identifiers belong here;
passwords, OTPs, recovery codes and bearer tokens must never be identifiers.

Categories distinguish password account/source, MFA account/challenge, recovery
account/challenge and enrollment challenge. Callers may choose category-specific
RateLimitPolicy values. An active-window policy mismatch fails closed instead of
silently raising a threshold; expired windows adopt the new policy. Counters
saturate at threshold+1 to prevent overflow. No Redis, per-worker allowance or
memory fallback exists. Database/configuration failures must prevent authentication.

Each admission decision must be committed before password/OTP/recovery work starts.
Check all relevant account/source/challenge categories, commit their counters,
then return a neutral denial if any is exhausted. Do not raise a 429 inside the
counter transaction and undo the attempt. Storage failure cannot yield an ALLOW
or continue to session creation. Source identifier trust/proxy configuration is a
Unit 6 deployment decision; do not trust arbitrary forwarding headers.

Configurable proposed initial defaults, all centralized in Settings:

| Setting | Default |
|---|---|
| `AUTH_SESSION_ABSOLUTE_SECONDS` | 1800 (30 minutes) |
| `AUTH_SESSION_IDLE_SECONDS` | 900 (15 minutes) |
| `AUTH_VERIFICATION_MAX_AGE_SECONDS` | 60 |
| `AUTH_CHALLENGE_LIFETIME_SECONDS` | 300 |
| `AUTH_CHALLENGE_MAX_ATTEMPTS` | 5 failed verifications |
| `AUTH_RATE_LIMIT_WINDOW_SECONDS` | 300 |
| `AUTH_RATE_LIMIT_THRESHOLD` | 5 |

These do not change existing JWT expiration settings. Idle lifetime may not exceed
absolute lifetime. Deployment must review category-specific thresholds, key
provisioning, expiry policy and clock synchronization before Unit 6 activation.

## Future integration and verification limits

The future normal flow for **every** canonical role is:

Anonymous → password verified → restricted enrollment/verification challenge →
real TOTP verification → committed MFA session → full application access.

Recovery is password verified → restricted recovery challenge → atomic single-use
code consumption → replacement enrollment → new TOTP verified → committed session.

The later dependency must reject legacy JWTs without valid persisted session IDs;
transport/cookie/CSRF/CORS decisions remain unchanged here. It must expose only the
fresh session-backed user/principal to Unit 4 consumers, which continue to perform
Unit 3 current organizational checks. An authenticated Super Admin still has no
automatic business-data access; `evaluate_access()` and Option B cutover remain
outside this unit.

PostgreSQL row-lock/UPSERT behavior is verified structurally/offline, not through a
live PostgreSQL connection. SQLite tests exercise conditional reuse prevention,
deterministic interleavings and shared counters. Its single in-memory connection
requires a serialized test harness for cooperating worker tests; this is not proof
of real multi-worker PostgreSQL runtime concurrency. Schedule a separately approved
disposable PostgreSQL concurrency check before deployment. Direct SQL/ORM writers
bypassing the locking protocol are outside the guarantee. Database lock/deadlock/
serialization failures fail closed; retry a whole fresh transaction where safe.

Expiry is logical, so stale evidence is retained. No cleanup/deletion task is
introduced; a future retention policy must preserve audit and security evidence.
No account-recovery helpdesk process, frontend screen, session transport or live
key provisioning is implemented in this foundation.

All verification uses the unchanged in-memory-only launcher. Migration tests run
only offline PostgreSQL DDL and compare full ORM/schema definitions. The existing
0007 migration test now checks its unchanged predecessor plus its new 0008
descendant; no prior security assertions or isolation safeguards were removed.

```powershell
.\.venv\Scripts\python.exe -u -B backend/scripts/run_phase1_tests.py backend/tests/test_test_isolation.py -q
.\.venv\Scripts\python.exe -u -B backend/scripts/run_phase1_tests.py backend/tests/test_authentication_infrastructure.py backend/tests/test_authentication_schema.py backend/tests/test_authentication_crypto_and_limits.py backend/tests/test_authentication_migration.py -q
.\.venv\Scripts\python.exe -u -B backend/scripts/run_phase1_tests.py backend/tests -q
git diff --check
```

Final verification: the pre-edit baseline passed 440 tests. The Unit 5 focused
suite passed 121 tests; the final complete backend suite passed 561 tests with the
same two pre-existing Starlette/Pydantic deprecation warnings. Isolation safeguards
passed 7/7, and the final full launcher reported 528 guarded engines, 527 in-memory
connections and 6 intentionally blocked unsafe isolation probes. Offline migration
checks opened no PostgreSQL connection. `git diff --check` passed.

The encryption dependency `cryptography==50.0.2` was added to requirements and
installed in the workspace `.venv`; no existing dependency was upgraded and no
lockfile was changed. No build, live migration, backfill, persistent key generation
or real-user credential/session operation was performed.

The Git-visible SHA-256 baseline contained 166 files. Unit 5 leaves 162 unchanged,
updates config/model registration/requirements/the migration-head assertion, and
adds 13 files. No existing files were removed. Previous model registration entries
and all prior-unit consumer, identity and isolation implementations were preserved.
