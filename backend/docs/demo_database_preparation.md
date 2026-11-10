# Guarded local evaluation database preparation

These tools are implemented but have NOT been approved for PostgreSQL execution.
They do not create databases, roles, instance markers, privileges or identities.
They never load normal application `.env` configuration. Run each command in a
fresh process. Passwords are prompted without echo, never accepted in URLs or
arguments. Descriptor files contain no passwords. Protect and independently
review the descriptor: this is operator-controlled local evaluation, not an
independent approval system or production provisioning boundary.

## Descriptor

Create a separately reviewed JSON descriptor outside version control, with exactly:

```json
{
  "target": {
    "host": "127.0.0.1",
    "port": 5432,
    "database": "fictional_evaluation",
    "schema_name": "public",
    "database_role": "fictional_app",
    "database_oid": 12345,
    "instance_id": "00000000-0000-0000-0000-000000000999",
    "disposable": true
  },
  "hostaddr": "127.0.0.1",
  "migration_owner_role": "fictional_owner",
  "application_role": "fictional_app"
}
```

All values above are fictional examples, NOT approved targets. Obtain actual OID,
port and identity from separately approved provisioning. The database comment must
be exactly `GNOSIS_LOCAL_DISPOSABLE_DEMO:<instance_id>`. Only loopback hosts and
the public schema are supported. The role in `target` must be the application
role; migration uses the explicitly declared, distinct database owner role.
No connection URL or query parameters are accepted. Migration also verifies
the actual database owner. Target checks are on the operation's own connection
and transaction. The existing bootstrap/serve command takes ONLY the inner
`target` object as its target file; it does not accept this wrapper descriptor.

`hostaddr` is mandatory and must be exactly `127.0.0.1` or `::1`; `target.host`
must be the same address or `localhost`. This pins the DBAPI network address
without DNS resolution. All inherited environment variable names beginning with
`PG` (case-insensitive), including service and host-address settings, cause a
generic rejection before engine creation and are checked again before every
DBAPI connection. Values are never displayed. Use a clean, explicitly configured
terminal rather than relying on libpq environment defaults; the tool does not
change the operator's environment. The PostgreSQL session's `inet_server_addr()`
must equal the pinned address before migration or loader writes. This check is
performed on the same connection and transaction as the protected operation.
Password prompts treat `GetPassWarning` as an error, aborting before echoed
fallback can accept credentials. This hardening applies to these preparation
commands; it does not change the existing bootstrap or server launcher's behavior.

## Proposed execution sequence (requires separate approval)

From `D:\projects\gnosis`, with an explicitly provisioned, approved database:

```powershell
# Dry-run: checks identity, owner, empty schema and reviewed graph, no DDL.
.\.venv\Scripts\python.exe -B backend/scripts/prepare_local_demo.py migrate --local-demo --ack-disposable-demo --target <reviewed-descriptor.json>
# Apply: explicit command + exact instance UUID confirmation.
.\.venv\Scripts\python.exe -B backend/scripts/prepare_local_demo.py migrate --local-demo --ack-disposable-demo --target <reviewed-descriptor.json> --apply-confirmation "APPLY:migrate:<instance-uuid>"
```

Migration is restricted to revision `0012`, uses absolute Alembic paths and the
existing migration files, and verifies the result before commit. Initial schema
must contain no schema-dependent objects. No upgrade of a partly prepared schema,
downgrade, reset or repair is offered. PostgreSQL transactional DDL must be rehearsed
on a separately approved disposable target. A dry-run checks the graph and target,
not successful execution or every DDL privilege.

Next, separately arrange application-role table privileges; use existing
`run_local_demo.py bootstrap` dry-run/apply/verify-existing with the inner target
file and `backend/demo/identities.example.json`. Bootstrap must precede the loader.
No identity creation is performed by these new tools.

```powershell
.\.venv\Scripts\python.exe -B backend/scripts/prepare_local_demo.py load-business-data --local-demo --ack-disposable-demo --target <reviewed-descriptor.json> --manifest backend/demo/identities.example.json --operator <operator-label>
.\.venv\Scripts\python.exe -B backend/scripts/prepare_local_demo.py load-business-data --local-demo --ack-disposable-demo --target <reviewed-descriptor.json> --manifest backend/demo/identities.example.json --operator <operator-label> --apply-confirmation "APPLY:load-business-data:<instance-uuid>"
```

No commands above have been run against PostgreSQL. Angle-bracket values are
placeholders to replace after review, not literal PowerShell arguments.

## Dataset and receipts

The fixed `fictional-business-v1` dataset matches the reviewed nine-user manifest
exactly. Resources `00000000-0000-0000-0000-000000000101` through `...109` cover
HR, Sales, Inventory, each in INTERNAL / CONFIDENTIAL / CRITICAL order.
Owners are fictional employee IDs `...005`, `...007`, `...009` respectively.
Each INTERNAL resource has 12 records; each other resource has 3 (54 total).
Record IDs are `demo-101-01` etc. Categories are
`SYNTHETIC_<DEPARTMENT>_<CLASSIFICATION>`. Values contain only synthetic=true,
a fictional item reference and quantity_units=ordinal*10.

No grants, department assignments, requests, authenticated actors, disclosures,
detections, risk results or sessions are created. Existing authorization decides
access; administrative status does not grant business-data access. Make explicit
department assignments through the existing authorized administration workflow.

One honest preparation audit record has a null actor (external operator), operator
label, deterministic receipt ID, dataset hash, manifest hash and target hash.
Resources, records and receipt commit atomically. JSON output appears only after
successful commit. Save it outside the repository if desired. Do not put secrets
in the operator label. Existing complete matching data is verified without writes;
partial, missing-receipt or conflicting data fails closed, never overwritten.
Unrelated resources are untouched; extra records within these nine resources fail.

If commit outcome is ambiguous, do not reset or rerun migration. Inspect the exact
approved target and revision under separate authorization. For data loading,
repeat the default dry-run: it recognizes a complete matching receipt/dataset.
An inconsistent state requires investigation, not automated repair.

## Limitations and pending checks

Mocked PostgreSQL probes and SQLite fixtures do not verify PostgreSQL DDL, row locks,
role privileges, driver behavior or concurrent external writers. Cooperating
bootstrap/load commands share an advisory transaction lock; identities and
departments are row-locked in ascending IDs. Run preparation with the demo stopped.
Application-role privileges must permit required inserts and row locks but must
not permit DDL. Connection/statement/lock waits use the existing bounded demo
options. A restore preserving every observed identity value cannot be detected;
stop the demo before restore/replacement and explicitly verify before restarting.
No production-grade host trust or universal restore protection is claimed.

The isolated preparation fixtures enable SQLite foreign-key enforcement. Tests
exercise the real Alembic environment's supplied-connection branch with a mocked
migration body, without executing migrations. They verify external transaction
ownership and exception propagation. Mocked CLI commit tests verify that receipts
are published only after commit, including suppression after commit failure;
these are not PostgreSQL commit or driver integration tests.
