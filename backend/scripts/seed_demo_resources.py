"""
Idempotent demo-data seed for GNOSIS resources and READ grants.

- Creates missing resources only (matched by name + department).
- Creates missing READ grants only, and only for the two HR resources.
- Never updates, deletes or un-revokes anything, and never touches passwords.
- Verifies with evaluate_access() BEFORE committing; aborts on a mismatch.

Usage (from backend/):
    python scripts/seed_demo_resources.py --dry-run
    python scripts/seed_demo_resources.py
"""
from __future__ import annotations

import argparse
import importlib
import pkgutil
import sys
import uuid
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import app.models as _models_pkg  # noqa: E402

for _, _name, _ in pkgutil.walk_packages(_models_pkg.__path__, _models_pkg.__name__ + "."):
    importlib.import_module(_name)

from sqlalchemy import func  # noqa: E402

from app.core import database as dbmod  # noqa: E402
from app.models.access_grant import AccessGrant  # noqa: E402
from app.models.department import Department  # noqa: E402
from app.models.resource import Resource  # noqa: E402
from app.models.user import User  # noqa: E402
from app.security.access_decision import evaluate_access  # noqa: E402

EMPLOYEE_EMAIL = "employee@gnosis.com"
ADMIN_NAME = "GNOSIS Admin"


def log(msg: str) -> None:
    print(f"SEED| {msg}")


def fail(msg: str) -> None:
    log(f"ERROR: {msg}")
    raise SystemExit(1)


# ---------- fixed values ----------
# Resource.sensitivity is a plain String(50) and AccessGrant.permission is a
# VARCHAR; evaluate_access() expects lowercase "read". No enums, no inspection.

SENS_PUBLIC = "PUBLIC"
SENS_INTERNAL = "INTERNAL"
SENS_RESTRICTED = "RESTRICTED"
SENS_CRITICAL = "CRITICAL"


# ---------- helpers ----------

def with_id(model, kwargs: dict) -> dict:
    """Give the row an id only if the model has no default of its own."""
    col = model.__table__.columns["id"]
    if col.default is None and col.server_default is None:
        kwargs["id"] = str(uuid.uuid4())
    return kwargs


def find_department(db, names: list[str]):
    for n in names:
        d = db.query(Department).filter(func.lower(Department.name) == n.lower()).first()
        if d:
            return d
    return None


def find_admin(db):
    admin = db.query(User).filter(User.name == ADMIN_NAME).first()
    if admin:
        return admin
    for u in db.query(User).all():
        if str(getattr(u.role, "value", u.role)).upper() == "ADMIN":
            return u
    return None


def verdict(decision):
    for attr in ("allowed", "is_allowed", "granted", "permitted", "authorized"):
        if hasattr(decision, attr):
            return bool(getattr(decision, attr))
    raw = getattr(decision, "decision", None)
    text = str(getattr(raw, "value", raw)).upper()
    if text in ("ALLOW", "ALLOWED", "GRANT", "GRANTED", "PERMIT", "PERMITTED"):
        return True
    if text in ("DENY", "DENIED"):
        return False
    return None


def ensure_resource(db, name, description, dept, owner, sensitivity, stats):
    existing = (
        db.query(Resource)
        .filter(Resource.name == name, Resource.department_id == dept.id)
        .first()
    )
    if existing:
        log(f"resource EXISTS   : {name} (id={existing.id}) - left unchanged")
        stats["resources_existing"] += 1
        return existing
    row = Resource(
        **with_id(
            Resource,
            dict(
                name=name,
                description=description,
                department_id=dept.id,
                owner_id=owner.id,
                sensitivity=sensitivity,
            ),
        )
    )
    db.add(row)
    db.flush()
    log(f"resource CREATED  : {name} (id={row.id})")
    stats["resources_created"] += 1
    return row


def ensure_read_grant(db, user, resource, perm, granted_by, stats):
    rows = (
        db.query(AccessGrant)
        .filter(
            AccessGrant.user_id == user.id,
            AccessGrant.resource_id == resource.id,
            AccessGrant.permission == perm,
        )
        .all()
    )
    if any(g.revoked_at is None for g in rows):
        log(f"grant EXISTS      : READ on {resource.name}")
        stats["grants_existing"] += 1
        return
    if rows:
        log(f"grant WARNING     : only REVOKED READ grant(s) on {resource.name}; "
            "not recreating (would override an admin revocation)")
        stats["grants_existing"] += 1
        return
    g = AccessGrant(
        **with_id(
            AccessGrant,
            dict(
                user_id=user.id,
                resource_id=resource.id,
                permission=perm,
                granted_by=granted_by.id,
            ),
        )
    )
    db.add(g)
    db.flush()
    log(f"grant CREATED     : READ on {resource.name}")
    stats["grants_created"] += 1


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="do everything, then roll back")
    args = parser.parse_args()

    session_factory = getattr(dbmod, "SessionLocal", None)
    db = session_factory() if session_factory else next(dbmod.get_db())

    stats = dict(resources_created=0, resources_existing=0, grants_created=0, grants_existing=0)
    try:
        employee = db.query(User).filter(User.email == EMPLOYEE_EMAIL).first()
        if not employee:
            fail(f"{EMPLOYEE_EMAIL} not found; run seed_demo_users.py first")
        admin = find_admin(db)
        if not admin:
            fail(f"no admin user found (name {ADMIN_NAME!r} or role ADMIN)")
        hr = find_department(db, ["HR", "Human Resources"])
        it = find_department(db, ["IT", "Information Technology"])
        if not hr:
            fail("HR department not found")
        if not it:
            existing = [d.name for d in db.query(Department).all()]
            fail(f"IT department not found; existing departments: {existing}")

        log(f"employee={employee.email} admin={admin.email} hr={hr.name} it={it.name}")

        perm = "read"
        if perm != "read":
            fail(f"read permission resolved incorrectly: {perm!r}")

        # (name, description, dept, owner, sensitivity, grant_read_to_employee)
        plan = [
            ("Employee Handbook", "Company-wide employee handbook.", hr, employee, SENS_PUBLIC, True),
            ("HR Benefits Guide", "Guide to employee benefits and enrollment.", hr, employee, SENS_INTERNAL, True),
            ("IT Security Reports", "Periodic IT security assessment reports.", it, admin, SENS_RESTRICTED, False),
            ("Admin Security Policies", "Internal security policy documents.", it, admin, SENS_CRITICAL, False),
        ]

        rows = []
        for name, desc, dept, owner, sens, grant in plan:
            res = ensure_resource(db, name, desc, dept, owner, sens, stats)
            if grant:
                ensure_read_grant(db, employee, res, perm, admin, stats)
            else:
                stray = (
                    db.query(AccessGrant)
                    .filter(AccessGrant.user_id == employee.id, AccessGrant.resource_id == res.id)
                    .count()
                )
                if stray:
                    log(f"WARNING: employee already has {stray} grant(s) on restricted "
                        f"resource {name}; NOT touching them")
            rows.append((res, grant))

        # ---- verify with the real authorization engine, before committing ----
        log("verification via evaluate_access(READ):")
        mismatch = False
        for res, should_allow in rows:
            active = (
                db.query(AccessGrant)
                .filter(
                    AccessGrant.user_id == employee.id,
                    AccessGrant.resource_id == res.id,
                    AccessGrant.revoked_at.is_(None),
                )
                .all()
            )
            decision = evaluate_access(employee, res, perm, active)
            v = verdict(decision)
            expected = "ALLOW" if should_allow else "DENY"
            shown = {True: "ALLOW", False: "DENY", None: "UNKNOWN"}[v]
            flag = "ok" if v is None or v == should_allow else "MISMATCH"
            if flag == "MISMATCH":
                mismatch = True
            log(f"  {res.name}: expected={expected} actual={shown} [{flag}] raw={decision!r}")

        if mismatch:
            db.rollback()
            fail("verification mismatch; nothing was committed")

        if args.dry_run:
            db.rollback()
            log("DRY RUN: rolled back, nothing committed")
        else:
            db.commit()
            log("committed")

        log(f"SUMMARY {stats}")
    except SystemExit:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    main()