# Stage 2: observational behavioural detection and risk

No score or detection grants, denies, disables, revokes or changes identity,
assignments, MFA, sessions or business permissions. No LLM is involved.
`evaluate_access()` remains unchanged. SecurityEvent is the existing detection
record; existing incident escalation is reused, not replaced by an alert system.

## Sources and capture

The existing detection engine flushes only; it never commits or rolls back its
caller's transaction. Audit service commits its best-effort audit first, then owns
a separate observation transaction. Administrative mutations retain their atomic
audit and run observation only after commit. The new business-record endpoint
commits its Stage 1 ledger first, then invokes best-effort monitoring in a separate
SQLAlchemy Session on the same bind. Monitoring failure is logged without driver
parameters and does not change the authorized response or committed ledger.
Replay is explicit: call evaluate_detection_rules(db, stored_audit) or
evaluate_disclosure_rules(db, response_id) inside a caller-owned transaction.
No background job, queue, public execution endpoint or automatic repair is added.

New resource access audits snapshot target department and sensitivity. Business
record attempts also correlate a server-generated response UUID and a SHA-256
session fingerprint. No raw session IDs/tokens or record payloads enter evidence.
Historical audits without snapshots remain incomplete; current resource ownership,
home department and present-day resource placement are never used to invent old
department activity. Legacy critical-resource classification can still use the
existing current-resource fallback when no sensitivity snapshot exists.

ALLOW is an attempt outcome, not disclosure. Only APPLICATION_COMPLETE ledger
rows contribute disclosure/record volume; their network transport remains UNKNOWN.
Denials, grants, pending requests and metadata add zero disclosed business records.
Failed/missing requests with no persisted audit are not guessed into the evidence.

## Rules and versioned constants

Defaults live in app/security/risk_scoring.py. These are demonstration constants;
changing thresholds/weights requires a scoring-policy version bump.

| Rule | Default window and threshold | Severity |
| --- | --- | --- |
| REPEATED_DENIED_ACCESS | 3 resource denials / 15 minutes | HIGH |
| CRITICAL_RESOURCE_ACCESS | One resource access attempt to CRITICAL data | DENY CRITICAL; ALLOW MEDIUM |
| CROSS_DEPARTMENT_ANOMALY | 2 distinct department-mismatch-denied resources / 10 minutes | HIGH |
| AFTER_HOURS_ACCESS | ALLOW at 22:00–05:00 UTC | LOW |
| REPEATED_SENSITIVE_DISCLOSURE | Sensitive records in 3 separate responses / 15 minutes | HIGH |
| BULK_DATA_DISCLOSURE | 10 distinct disclosed record IDs / 15 minutes | HIGH |
| REQUEST_FREQUENCY_ANOMALY | 10 business-record access attempts / 15 minutes | MEDIUM |
| DEPARTMENT_HOPPING | Activity across 3 actual target departments / 15 minutes | LOW; HIGH if also 3 denials |

Sensitive means CONFIDENTIAL or CRITICAL. Repeat-sensitive counts response IDs,
not rows from one response. Bulk counts distinct record IDs, not duplicate reads.
Hopping uses department snapshots, never resource counts; legitimate granted
cross-department work is explicitly a review signal, not an authorization violation.
The original CROSS_DEPARTMENT_ANOMALY retains its resource-probing meaning.
Resource-specific rules ignore unrelated audit actions.

Each event freezes rule/version, timestamps, window, observed count, threshold,
explanation, audit/disclosure/security-event references and evidence scope. Windows
are inclusive at both ends for assessment evaluation; API date filters use start
inclusive/end exclusive. Future evidence is excluded. Deduplication uses durable
unique SHA-256 episode keys over policy, actor, rule, severity and a fixed UTC
15-minute bucket; CRITICAL_RESOURCE_ACCESS also partitions by resource. A later
critical denial cannot be suppressed by an earlier allowed access. Bucket boundaries
may produce two nearby episodes. Counts/evidence freeze at first threshold crossing;
later activity remains in audits/ledger and later assessments, not repeated alerts.
Episode and incident linkage are in the same transaction/savepoint. Uniqueness
conflicts are treated as retries only if an existing matching episode is proven.

## Pure scoring policy gnosis-observe-v1

Each active factor contributes its fixed weight once, inactive/missing factors zero.
Score = min(100, sum(contributions)); these are ordinal review priorities, not
probabilities or calibrated estimates of maliciousness.

| Factor | Trigger | Weight |
| --- | --- | --- |
| sensitivity | Any sensitive disclosure | 10 |
| distinct_records | At least 5 distinct disclosed records | 10 |
| repeated_sensitive | At least 3 sensitive responses | 15 |
| bulk | At least 10 distinct disclosed records | 20 |
| frequency | At least 10 business-record attempts | 15 |
| department_hopping | At least 3 actual target departments | 10 |
| denials | At least 3 denied resource attempts | 15 |
| security_severity | Existing HIGH or CRITICAL event in the window | 15 |

LOW 0–24; MEDIUM 25–49; HIGH 50–74; CRITICAL 75–100. Event severity and risk level
are distinct. Existing detection severity contributes a bounded contextual factor,
not an automatic CRITICAL assessment. Overlapping volume factors intentionally
represent increasing review priority; no undocumented multipliers exist.

REQUEST assessments match the response UUID (or legacy audit ID), SESSION matches
the opaque fingerprint, EMPLOYEE covers the actor's rolling 15-minute window.
Request/session metrics are filtered, not copied from employee totals. A linked
detection can provide broader contextual evidence; all its departments remain in
visibility scope. The policy, factors, metrics, source references, event timestamp
and window are persisted. Pre-disclosure request and post-disclosure assessments
are distinct immutable snapshots. Fingerprints deduplicate identical evaluations.
Missing evidence is zero contribution, never a declaration of safety. Evidence
coverage is recorded; transport certainty is always UNKNOWN. No historical backfill
or periodic idle-session refresh occurs. "Latest" means latest recorded assessment,
not a freshly recomputed score at read time.

## Monitoring and scope

- GET /monitoring/detections
- GET /monitoring/risk-assessments (scope REQUEST, SESSION or EMPLOYEE; scope_key)
- GET /monitoring/risk/employees/{employee_id}
- GET /monitoring/risk/sessions/{session_ref}

All support timezone-qualified start/end and bounded limit/offset pagination.
Generic lists also accept employee_id. Employee/session summaries return the latest
visible snapshot plus paginated history. A null latest means no visible assessment,
not LOW risk. Scope is applied before all filters/counts/pagination.

Existing global security-monitor authority grants Super Admin visibility. Ordinary
employees receive 403. Department Admins require current explicit assignments for
every contributing evidence department. Unknown scope fails closed. Cross-scope
assessments are hidden whole, not shown with global counts or partially redacted
factors. Existing security-event, incident, dashboard and investigator consumers
also enforce complete new-event evidence scope. Legacy events retain their existing
resource-based scope behavior. No broadening of business-data access is introduced.

## Migration and limitations

Revision 0012 depends on actual revision 0011 (filename is not its revision ID).
Adds nullable event evidence/episode columns, a unique episode constraint and risk
assessment/scope tables. No earlier migration or historical row is rewritten.
Downgrade refuses destructive evidence removal. Tests verify PostgreSQL DDL offline
and portable table creation in memory; PostgreSQL ALTER/concurrency are unverified.

This bounded academic implementation reads actor/window evidence into memory; it
does not scan the entire organization. Very high event volume will require query
aggregation and retention controls. Offset pagination can shift under new writes.
Recorded scores can be stale, best-effort processing can fail and require replay,
and no production multi-worker/concurrency or live HTTPS readiness is claimed.
