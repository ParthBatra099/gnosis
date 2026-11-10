# Incident coordination and immutable evidence

Published audit events, security events and monitoring scopes are read without
row locks. Current publishers insert a detection and all its scopes in one outer
transaction; no application service amends published evidence. Runtime ACLs must
withhold UPDATE and DELETE on these tables and on resource metadata. INSERT
permission alone does not enforce complete/immutable scope publication against
arbitrary SQL. Database-owner changes and future metadata-editing services are
outside this protocol and require separate review.

Manual incident mutations use one explicit transaction for authorization, changes
and strict audit. They acquire all existing users in ascending ID order, then all
existing departments in ascending ID order, using FOR NO KEY UPDATE. This is a
deliberately coarse, low-volume coordination scheme matching organization
management's ascending user order. It protects assignment/role/department state
without blocking foreign-key KEY SHARE locks from evidence insertion. Authority
is still freshly revalidated; complete-scope predicates are unchanged. Existing
incident rows are locked FOR UPDATE and refreshed before checking membership.

Automatic escalation takes pg_advisory_xact_lock(1196314451, 1229865796), the
namespaced ASCII GNOS/INCD pair, before detection insertion and before selecting
an active incident. The single coarse key serializes all automatic find-or-create
operations, including absent rows, until the caller's outer commit or rollback.
It refreshes the selected incident under the same parent row lock as manual
writers, re-searching if a manual writer resolved/closed it while it waited.
Both writers recheck and flush links under that parent lock. Newly created
incidents are private to their creating transaction until commit. Manual creation
may intentionally create a separate incident; no new grouping policy is imposed.

Automatic writers must not acquire identity/department write locks after taking
the advisory/incident locks. Manual writers must not acquire the escalation
advisory lock while holding incident locks. Post-commit detection uses a new
transaction after manual locks have been released. No session-scoped advisory
locks, new connections, independent commits or schema changes are introduced.

The protocol assumes PostgreSQL READ COMMITTED and immutable runtime resource
metadata. Locks and advisory locks are released by the caller's transaction.
Timeouts and database exceptions propagate to that transaction's rollback;
existing best-effort monitoring callers retain their committed source evidence.
No automatic retry or session-level timeout configuration is added. Deployment
must supply bounded lock/statement waits. The application role needs permission
to execute pg_advisory_xact_lock if the installation restricts function EXECUTE.

SQLite regressions exercise actual service transactions, failures, deterministic
interleavings and PostgreSQL SQL compilation. They do not establish PostgreSQL
row-lock, advisory-lock, isolation or privilege guarantees. A separately approved
PostgreSQL contention rehearsal remains required. This coarse scheme reduces
concurrency; narrower lock sets require a separately reviewed discovery/retry
protocol. New users/departments are not protected by existing-row locks, but new
identities cannot become the request's authenticated actor or assignee implicitly.
