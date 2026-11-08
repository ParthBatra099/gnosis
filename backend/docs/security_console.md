# Stage 3 security console and timeline

The console projects existing AuditEvent, DataDisclosure, SecurityEvent,
RiskAssessment, Incident and IncidentEvent records. No migration, alert table,
duplicate event store, scoring policy or authentication change is introduced.
The Alembic head remains 0012. Stage 1/2 capture and observation semantics remain.

## APIs

- GET /console/dashboard/security-overview: scoped persisted metrics, default
  preceding seven days, with timezone-aware optional start/end. Detection and
  disclosure counts use that period. Employee elevated-risk counts use the latest
  visible EMPLOYEE assessment per actor in the period (HIGH/CRITICAL), not the
  number of historical high scores. Up to five employee assessments, detections
  and timeline entries are included. Incident status counts are current across
  all dates, explicitly labelled in the UI. Original /dashboard/summary unchanged.
- GET /monitoring/detections: existing bounded list now accepts severity,
  event_type (exact identifier) and incident_status. Related incident references
  contain only currently visible incidents. An invisible linked incident never
  affects a status-filtered count. Existing Stage 2 evidence is reused.
- GET /console/incidents/page: bounded list with status, severity, creation-time
  start/end, limit (1–100, default 25) and offset (>=0). Original list contract
  remains unchanged. Must appear before the dynamic incident detail route.
- GET /console/incidents/{id}: existing detail additionally returns scoped
  detection_evidence and recorded audit history (action, actor, timestamp, status).
  Current resolution_notes and existing assignee/reporter IDs are shown. Notes
  are not historically reconstructed when old audit rows did not snapshot them.
- PATCH /console/incidents/{id}: existing lifecycle and CSRF contract, unchanged.
  OPEN -> INVESTIGATING -> RESOLVED -> CLOSED. Resolution requires notes.
- GET /monitoring/timeline: union projection of five scoped evidence sources;
  returns items,total,limit,offset. Filters: employee_id, session_ref (opaque hash),
  category, severity, timezone-aware start/end; default limit 25, maximum 100.

Timeline categories: ACCESS_ALLOWED, ACCESS_DENIED, DATA_DISCLOSED,
SECURITY_DETECTION, RISK_ASSESSMENT, INCIDENT_CREATED, INCIDENT_UPDATED, AUDIT_EVENT.
The incident row supplies creation time for both manual and automatic incidents;
the corresponding manual creation audit is not duplicated. Updates come from
persisted audits, not invented transitions. Severity filters apply only to sources
with a severity/level; access outcomes are not fabricated severity values.

Start is inclusive, end exclusive. Rows order by timestamp descending, then source
and source ID for deterministic ties. Offset pages can shift during new writes.
Employee filtering includes an incident's reporter/linked-event employee while
retaining the actual update actor in the entry. Session filtering matches only
known hashes; it does not infer missing session associations for incident actions.

## Privacy and accuracy

All sources use the current central administrative authority/scope predicates
before grouping, filters, counts or paging. Employees receive 403. Department
Admin scope comes exclusively from current explicit assignments. Full evidence
scope remains mandatory for combined assessments, detections and incidents.
Incident audit entries in the shared audit predicate and timeline require visibility of their whole referenced incident,
even if the audit's resource alone would be visible. Related links obey the same
rule. Authentication/identity audits without resource scope remain global-monitor
only under existing rules. No new home-department authority is inferred.

Timeline audit records use an explicit field projection and never return arbitrary
context_data, credentials, raw tokens or business-record values. Session references
are one-way correlation hashes. Source IDs, classifications and scoped generated
risk/detection evidence are shown; no business-record payloads are joined.
Disclosure is labelled application-prepared with UNKNOWN transport, never receipt.
ALLOW is a decision about an attempt, not disclosure. DENY adds no data exposure.

## Frontend

/admin now shows server-backed metrics without sample values. Existing security
events, incidents and audit placeholder pages are implemented; /admin/timeline is
added beneath the existing canonical administrative route guard. Navigation is
enabled only for canonical Super/Department Admin roles, without legacy fallback.
The existing Axios cookie/CSRF transport is reused. Frontend risk is presentation
only; scoring is never recomputed there. Filters use local datetime inputs converted
to UTC, pages are bounded to 20 items, and incident updates require explicit review.

Read failures clear displayed evidence; session rejection cancels pending reads
so stale responses cannot restore data. Mutation denial does not auto-retry. A
successful write followed by failed refresh is reported distinctly. Role guards are
presentation only; the backend remains authoritative on every request. Current
authority is refreshed on explicit reload/navigation, not through a live stream.

## Verification limits

Backend tests run through the unchanged in-memory SQLite launcher. Timeline SQL is
also compiled offline for PostgreSQL; no PostgreSQL runtime/concurrency or migration
is claimed. Frontend tests use mocked Axios and React server rendering/controller
execution, not a live browser or HTTPS backend. Production build is static validation.
Existing incident-detail payloads include linked evidence/history without separate
history pagination; list/timeline APIs are bounded. No live delivery, deployment
readiness, background monitoring reliability or production scale is certified.
