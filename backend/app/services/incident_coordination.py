"""Incident writer coordination; never locks or changes immutable evidence.

Manual writers lock identities, departments, then the incident. Automatic writers
take one namespaced transaction advisory lock before publishing detections, then
lock the selected incident. They never subsequently acquire identity/department
write locks. Foreign-key KEY SHARE locks remain compatible with manual parent
NO KEY UPDATE locks. The coarse advisory lock deliberately serializes automatic
find-or-create across all groups, including the absent-row case; no hash or DNS.

SQLite tests exercise ordering/rollback, not PostgreSQL locking semantics.
"""
from sqlalchemy import func, select

from app.models.incident import Incident
from app.models.incident_event import IncidentEvent


def serialize_escalation(db):
    if not db.in_transaction():
        raise RuntimeError("Incident coordination requires a caller transaction")
    if db.get_bind().dialect.name == "postgresql":
        # Two stable signed-int32 keys: ASCII GNOS / INCD. Transaction-owned only.
        db.execute(select(func.pg_advisory_xact_lock(0x474E4F53, 0x494E4344)))


def lock_incident_row(db, incident_id):
    """Refresh only after acquiring the common mutable-parent lock."""
    return db.query(Incident).filter_by(id=incident_id).with_for_update().populate_existing().first()


def attach_events(db, incident, event_ids):
    """Caller owns a new incident or holds its row lock until commit.

    Flush each link under the lock: autoflush is intentionally disabled by callers,
    so repeated attachments in the same transaction must also see pending links.
    """
    for event_id in sorted(set(event_ids)):
        if not db.query(IncidentEvent.id).filter_by(
                incident_id=incident.id, security_event_id=event_id).first():
            db.add(IncidentEvent(incident_id=incident.id, security_event_id=event_id))
            db.flush()
