# Stage 1 disclosure evidence

`GET /resources/{resource_id}/records?limit=25&offset=0` returns at most 100
synthetic records after the unchanged `evaluate_access(..., "read", grants)` check.
It never accepts SQL, table names, payloads, role claims or response IDs from clients.
Existing resource, assistant and catalog responses remain metadata, not record exposure.

## Demonstration dataset

`app.services.exposure_service.synthetic_records(resource_id)` constructs three
deterministic fictional budget records (IDs `<resource-id>:demo:1` through `:3`).
The factory does not connect or write. In an independently approved disposable
demo database, an operator can add these objects in an explicit SQLAlchemy
transaction against a selected INTERNAL resource. There is no startup seed,
public write API, migration data seed or existing database execution. Isolated
tests demonstrate the complete setup. No real personal/financial values belong here.
Records inherit department association through their resource; evidence snapshots
that department. Each returned record must match its resource sensitivity, otherwise
the endpoint fails closed rather than exposing higher-classified content.

## Completion and failure semantics

The endpoint validates records and serializes the entire non-streaming response
before capture. Capture and commit must succeed before the new endpoint returns;
otherwise it rolls back all disclosure rows and responds 503 without business values.
This is an explicit policy for this new representation, not a change to existing
best-effort audit logging or any authorization policy. Empty results add no rows.

`APPLICATION_COMPLETE` means the application response is fully prepared for return.
`transport_state=UNKNOWN` always: it does not prove HTTP transport completion,
client receipt, reading or retention. A disconnect after commit can leave evidence
of a prepared response that was not delivered. No network-delivery claim is made.

Each ledger row describes one record in one response. Reprocessing the same
response/record is idempotent; conflicting identities fail. A database unique
constraint rejects simultaneous duplicates; callers retry the entire transaction
after rollback. An HTTP retry is a genuinely new response with a new server UUID.
Ledger rows contain IDs/classifications only, never record values. Session correlation
is a one-way SHA-256 fingerprint of the validated opaque session ID, never a token.

## Monitoring

- `GET /monitoring/exposure/summary`
- `GET /monitoring/exposure/employees/{employee_id}`
- `GET /monitoring/exposure/events?limit=25&offset=0`

All accept timezone-qualified `start` (inclusive), `end` (exclusive), and optional
`session_ref`. Events also accept `employee_id`. Scope is applied before totals,
grouping, filtering and pagination. Super Admin uses existing global monitoring
authority. Department Admin sees only evidence whose snapshot department is currently
assigned. Resource moves do not move old evidence. Employees receive 403. Out-of-scope
employee filters return empty scoped results without confirming account existence.

Summary event counts mean record-disclosure rows, not HTTP responses. Distinct counts
use globally stable record IDs; repeated disclosures = events minus distinct records.
Groups include sensitivity, business category, snapshot department, employee and
session (null means unavailable). Group totals can overlap for distinct records.
Events are ordered timestamp descending, then ID descending. Offset pagination may
shift under new writes; no snapshot consistency across separate requests is promised.

Revision `0011` adds two tables/indexes only, parent `0010_phase2_identity_validation`.
No historical ALLOW audit is backfilled into exposure. Destructive downgrade refuses
to discard evidence; use reviewed recovery or a forward fix. PostgreSQL runtime
upgrade/concurrency and live delivery are not verified by SQLite/offline tests.
