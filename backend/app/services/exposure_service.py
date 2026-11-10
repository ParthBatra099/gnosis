"""Disclosure accounting only. Never contributes an authorization decision."""
import hashlib
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import func, select

from app.models import BusinessRecord, DataDisclosure
from app.services import administrative_access as admin


def retrieve_records(db, resource, *, limit=25, offset=0):
    """Fixed repository query; caller must authorize read of this resource first."""
    if type(limit) is not int or not 1 <= limit <= 100 or type(offset) is not int or offset < 0:
        raise ValueError("Invalid business-record page")
    records = db.scalars(select(BusinessRecord).where(BusinessRecord.resource_id == resource.id)
                         .order_by(BusinessRecord.id).offset(offset).limit(limit)).all()
    if any(record.sensitivity != resource.sensitivity for record in records):
        raise HTTPException(503, "Business record classification inconsistent")
    return records


def record_disclosures(db, *, actor_id, resource, records, response_id, session_id=None, timestamp=None):
    """Caller commits. Same response/record is immutable and idempotent.

    A uniqueness constraint also rejects concurrent duplicate writers atomically.
    Such a writer must retry its entire transaction, never a partial batch.
    """
    timestamp = timestamp or datetime.now(timezone.utc)
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("Timezone-aware disclosure timestamp required")
    ref = hashlib.sha256(session_id.encode()).hexdigest() if session_id else None
    for record in {r.id: r for r in records}.values():
        if record.resource_id != resource.id or db.get(BusinessRecord, record.id) is not record:
            raise ValueError("Record does not belong to the disclosed resource")
        expected = dict(actor_id=actor_id, resource_id=resource.id, department_id=resource.department_id,
                        category=record.category, sensitivity=record.sensitivity, session_ref=ref)
        existing = db.scalar(select(DataDisclosure).where(
            DataDisclosure.response_id == response_id, DataDisclosure.record_id == record.id))
        if existing:
            if any(getattr(existing, key) != value for key, value in expected.items()):
                raise ValueError("Conflicting disclosure response identity")
            continue
        db.add(DataDisclosure(response_id=response_id, record_id=record.id,
                              timestamp=timestamp.astimezone(timezone.utc), **expected))
    db.flush()


def scoped_disclosures(db, actor_id):
    if admin.global_monitor(db, actor_id):
        return select(DataDisclosure)
    ids = admin.departments(db, actor_id, admin.A.DEPARTMENT_SECURITY_MONITOR)
    if not ids:
        raise HTTPException(403, "Exposure monitoring not authorized")
    return select(DataDisclosure).where(DataDisclosure.department_id.in_(ids))


def filtered_disclosures(db, actor_id, *, employee_id=None, start=None, end=None, session_ref=None):
    query = scoped_disclosures(db, actor_id)
    for value in (start, end):
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise HTTPException(422, "Time bounds must include a timezone")
    if start and end and start >= end:
        raise HTTPException(422, "start must precede end")
    if employee_id:
        query = query.where(DataDisclosure.actor_id == employee_id)
    if start:
        query = query.where(DataDisclosure.timestamp >= start.astimezone(timezone.utc))
    if end:
        query = query.where(DataDisclosure.timestamp < end.astimezone(timezone.utc))
    if session_ref:
        query = query.where(DataDisclosure.session_ref == session_ref)
    return query


def summarize(db, query):
    rows = query.subquery()
    def counts(statement):
        return [dict(row._mapping) for row in db.execute(statement)]
    total, distinct = db.execute(select(func.count(), func.count(func.distinct(rows.c.record_id))).select_from(rows)).one()
    groups = {}
    for label, column in (("by_sensitivity", rows.c.sensitivity), ("by_category", rows.c.category),
                          ("by_department", rows.c.department_id), ("by_employee", rows.c.actor_id),
                          ("by_session", rows.c.session_ref)):
        groups[label] = counts(select(column.label("key"), func.count().label("disclosure_events"),
                                      func.count(func.distinct(rows.c.record_id)).label("distinct_records"))
                               .group_by(column).order_by(column))
    return dict(disclosure_events=total, distinct_records=distinct, repeated_disclosures=total-distinct, **groups)


def synthetic_records(resource_id):
    """Explicit fixture factory; no startup seeding, database writes or real values."""
    return [BusinessRecord(id=f"{resource_id}:demo:{i}", resource_id=resource_id,
                           category="SYNTHETIC_BUDGET", sensitivity="INTERNAL",
                           values={"project": f"Fictional Project {i}", "budget_units": i * 100})
            for i in (1, 2, 3)]
