"""
Idempotent FULL demo-data seed for GNOSIS (departments, users, resources, grants).

- Creates missing departments, users, resources and "read" grants only.
- Existing rows are left untouched (no updates, no deletes).
- Never changes a password of an existing user.
- Never revokes / un-revokes / modifies grants.
- Never touches models, migrations, evaluate_access() or audit/security events.
- Verifies with the REAL evaluate_access() BEFORE committing; any mismatch on a
  hard expectation rolls everything back and exits with an error.

Usage (from backend/):
    python scripts/seed_full_demo_data.py --dry-run
    python scripts/seed_full_demo_data.py
"""
from __future__ import annotations

import argparse
import enum
import importlib
import inspect
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

PERM_READ = "read"  # exact string expected by evaluate_access()

EXISTING_ADMIN_EMAIL = "admin@gnosis.com"

# ---------------------------------------------------------------- demo plan

# key -> names to look for (first match wins) ; first name is used when creating
DEPARTMENTS: dict[str, list[str]] = {
    "IT": ["IT", "Information Technology"],
    "HR": ["HR", "Human Resources"],
    "Sales": ["Sales"],
    "Finance": ["Finance"],
}
DEPARTMENT_DESCRIPTIONS = {
    "IT": "Information Technology",
    "HR": "Human Resources",
    "Sales": "Sales",
    "Finance": "Finance",
}

# requested role -> roles to try, in order (least privilege fallback)
ROLE_FALLBACKS: dict[str, list[str]] = {
    "ADMIN": ["ADMIN"],
    "MANAGER": ["MANAGER", "EMPLOYEE"],
    "SECURITY_OFFICER": ["SECURITY_OFFICER", "EMPLOYEE"],
    "EMPLOYEE": ["EMPLOYEE"],
}

USERS = [
    dict(name="Parth Batra", email="parth@gnosis.com", role="ADMIN", dept="IT", password="Parth@12345"),
    dict(name="Prapti Gupta", email="prapti@gnosis.com", role="MANAGER", dept="HR", password="Prapti@12345"),
    dict(name="Om Sharma", email="om@gnosis.com", role="SECURITY_OFFICER", dept="IT", password="Om@12345"),
    dict(name="Aarav Mehta", email="aarav@gnosis.com", role="EMPLOYEE", dept="Finance", password="Aarav@12345"),
    dict(name="Riya Kapoor", email="riya@gnosis.com", role="EMPLOYEE", dept="Sales", password="Riya@12345"),
    dict(name="Kunal Verma", email="kunal@gnosis.com", role="EMPLOYEE", dept="HR", password="Kunal@12345"),
]

OWNER_BY_DEPT = {
    "IT": "parth@gnosis.com",
    "HR": "prapti@gnosis.com",
    "Sales": "riya@gnosis.com",
    "Finance": "aarav@gnosis.com",
}

# (name, dept key, sensitivity, description)
RESOURCES = [
    ("Employee Handbook", "HR", "PUBLIC", "Company-wide employee handbook."),
    ("HR Benefits Guide", "HR", "INTERNAL", "Guide to employee benefits and enrollment."),
    ("Employee Performance Records", "HR", "RESTRICTED", "Employee performance review records."),
    ("IT Security Reports", "IT", "RESTRICTED", "Periodic IT security assessment reports."),
    ("Admin Security Policies", "IT", "CRITICAL", "Internal security policy documents."),
    ("Infrastructure Documentation", "IT", "INTERNAL", "Systems and infrastructure documentation."),
    ("Sales Pipeline", "Sales", "INTERNAL", "Current sales pipeline and forecasts."),
    ("Customer Accounts", "Sales", "RESTRICTED", "Customer account records."),
    ("Financial Reports", "Finance", "RESTRICTED", "Quarterly and annual financial reports."),
    ("Payroll Records", "Finance", "CRITICAL", "Employee payroll records."),
]

# Minimum grants: (user email, dept key, resource name). All are "read".
# No grant is ever created for a cross-department user or on a CRITICAL resource.
GRANTS = [
    ("employee@gnosis.com", "HR", "Employee Handbook"),
    ("employee@gnosis.com", "HR", "HR Benefits Guide"),
    ("kunal@gnosis.com", "HR", "Employee Handbook"),
    ("kunal@gnosis.com", "HR", "HR Benefits Guide"),
    ("om@gnosis.com", "IT", "IT Security Reports"),
    ("om@gnosis.com", "IT", "Infrastructure Documentation"),
]

# Verification: (label, user email, dept key, resource name, expected)
#   expected True/False = HARD expectation (mismatch -> rollback + error)
#   expected None       = informational: report what the real engine says
CHECKS = [
    ("HR user -> IT restricted resource", "kunal@gnosis.com", "IT", "IT Security Reports", False),
    ("HR user -> Finance critical resource", "kunal@gnosis.com", "Finance", "Payroll Records", False),
    ("Sales user -> Finance restricted resource", "riya@gnosis.com", "Finance", "Financial Reports", False),
    ("Sales user -> IT critical resource", "riya@gnosis.com", "IT", "Admin Security Policies", False),
    ("Finance user -> Sales restricted resource", "aarav@gnosis.com", "Sales", "Customer Accounts", False),
    ("Finance user -> HR restricted resource", "aarav@gnosis.com", "HR", "Employee Performance Records", False),
    ("Parth -> IT restricted resource", "parth@gnosis.com", "IT", "IT Security Reports", None),
    ("Parth -> IT critical resource", "parth@gnosis.com", "IT", "Admin Security Policies", None),
    ("Prapti -> HR public resource", "prapti@gnosis.com", "HR", "Employee Handbook", None),
    ("Prapti -> HR restricted resource", "prapti@gnosis.com", "HR", "Employee Performance Records", None),
    ("Om -> IT restricted resource (has grant)", "om@gnosis.com", "IT", "IT Security Reports", None),
    ("Om -> IT critical resource (no grant)", "om@gnosis.com", "IT", "Admin Security Policies", None),
    ("Kunal -> HR public resource (has grant)", "kunal@gnosis.com", "HR", "Employee Handbook", None),
    ("Riya -> Sales internal resource", "riya@gnosis.com", "Sales", "Sales Pipeline", None),
    ("Aarav -> Finance critical resource", "aarav@gnosis.com", "Finance", "Payroll Records", None),
    ("Demo Employee -> HR internal resource", "employee@gnosis.com", "HR", "HR Benefits Guide", None),
]


# ------------------------------------------------------------------ helpers

def log(msg: str) -> None:
    print(f"DEMO| {msg}")


def fail(msg: str) -> None:
    log(f"ERROR: {msg}")
    raise SystemExit(1)


def with_id(model, kwargs: dict) -> dict:
    """Give the row an id only if the model has no default of its own."""
    col = model.__table__.columns["id"]
    if col.default is None and col.server_default is None:
        kwargs["id"] = str(uuid.uuid4())
    return kwargs


def enum_text(value) -> str:
    if isinstance(value, enum.Enum):
        return str(value.name).upper()
    return str(value).upper()


# ---------------------------------------------------------------- passwords

class PasswordMaker:
    """Argon2 hashing via pwdlib (same scheme as existing users)."""

    def __init__(self) -> None:
        try:
            from pwdlib import PasswordHash

            self._hasher = PasswordHash.recommended()
        except Exception as exc:  # ImportError or missing argon2 extra
            fail(f"cannot initialise pwdlib Argon2 hasher: {exc!r}")
        self._project_checked = False

    def _project_verifier(self):
        for modname in (
            "app.core.security",
            "app.security.passwords",
            "app.security.password",
            "app.core.passwords",
        ):
            try:
                mod = importlib.import_module(modname)
            except Exception:
                continue
            for fname in ("verify_password", "verify_password_hash", "check_password"):
                fn = getattr(mod, fname, None)
                if callable(fn):
                    return f"{modname}.{fname}", fn
        return None, None

    def hash(self, plain: str) -> str:
        hashed = self._hasher.hash(plain)
        if not self._hasher.verify(plain, hashed):
            fail("pwdlib self-check failed: freshly created hash does not verify")
        if not self._project_checked:
            self._project_checked = True
            name, fn = self._project_verifier()
            if fn is None:
                log("password check: project verify function not found; pwdlib self-check passed")
            else:
                ok = False
                for args in ((plain, hashed), (hashed, plain)):
                    try:
                        if fn(*args) is True:
                            ok = True
                            break
                    except Exception:
                        continue
                if ok:
                    log(f"password check: {name} accepts the generated hash")
                else:
                    log(f"WARNING: {name} did not confirm the generated hash; "
                        "test a demo login after seeding")
        return hashed


# -------------------------------------------------------------------- roles

class RoleResolver:
    def __init__(self, db) -> None:
        col = User.__table__.columns["role"]
        self.enum_cls = getattr(col.type, "enum_class", None)
        self.supported: set[str] = set()
        self.sources: list[str] = []

        if self.enum_cls is not None:
            self.mode = "SQLAlchemy Enum column"
            for m in self.enum_cls:
                self.supported.add(m.name.upper())
                self.supported.add(str(m.value).upper())
            self.sources.append(f"{self.enum_cls.__module__}.{self.enum_cls.__name__}")
        else:
            self.mode = "plain string column"
            for e in getattr(col.type, "enums", None) or []:
                self.supported.add(str(e).upper())
                self.mode = "string Enum column"
            if self.supported:
                self.sources.append("column enum values")

        if not self.supported:
            self._scan_role_enums()
        if not self.supported:
            self._import_extra_modules()
            self._scan_role_enums()

        existing = {enum_text(r) for (r,) in db.query(User.role).distinct().all()}
        if not self.supported:
            self.supported = existing | {"ADMIN", "EMPLOYEE"}
            self.sources.append("roles already in users table + ADMIN/EMPLOYEE (no role enum found)")
        else:
            self.supported |= existing

    def _scan_role_enums(self) -> None:
        for modname, mod in list(sys.modules.items()):
            if not modname.startswith("app.") or mod is None:
                continue
            for _n, obj in list(vars(mod).items()):
                if (
                    inspect.isclass(obj)
                    and issubclass(obj, enum.Enum)
                    and obj.__module__ == modname
                    and "role" in obj.__name__.lower()
                ):
                    for m in obj:
                        self.supported.add(m.name.upper())
                        self.supported.add(str(m.value).upper())
                    self.sources.append(f"{modname}.{obj.__name__}")

    def _import_extra_modules(self) -> None:
        for pkg_name in ("app.schemas", "app.core", "app.security"):
            try:
                pkg = importlib.import_module(pkg_name)
            except Exception:
                continue
            for _, sub, _ in pkgutil.walk_packages(getattr(pkg, "__path__", []), pkg_name + "."):
                try:
                    importlib.import_module(sub)
                except Exception:
                    continue

    def resolve(self, requested: str) -> str:
        for cand in ROLE_FALLBACKS[requested]:
            if cand in self.supported:
                return cand
        fail(f"no supported role available for requested role {requested}; "
             f"supported = {sorted(self.supported)}")
        raise AssertionError  # unreachable

    def to_stored(self, role_name: str):
        if self.enum_cls is not None:
            for m in self.enum_cls:
                if m.name.upper() == role_name or str(m.value).upper() == role_name:
                    return m
            fail(f"role {role_name} not found in {self.enum_cls}")
        return role_name


# --------------------------------------------------------------- ensure_* ops

def find_department(db, key: str):
    for n in DEPARTMENTS[key]:
        d = db.query(Department).filter(func.lower(Department.name) == n.lower()).first()
        if d:
            return d
    return None


def ensure_department(db, key: str, stats: dict):
    d = find_department(db, key)
    if d:
        log(f"department EXISTS : {d.name}")
        stats["departments_existing"] += 1
        return d
    d = Department(
        **with_id(
            Department,
            dict(name=DEPARTMENTS[key][0], description=DEPARTMENT_DESCRIPTIONS[key]),
        )
    )
    db.add(d)
    db.flush()
    log(f"department CREATED: {d.name}")
    stats["departments_created"] += 1
    return d


def ensure_user(db, spec: dict, dept, roles: RoleResolver, passwords: PasswordMaker, stats: dict):
    existing = db.query(User).filter(func.lower(User.email) == spec["email"].lower()).first()
    if existing:
        log(f"user EXISTS       : {existing.name} <{existing.email}> - left unchanged "
            "(password NOT touched)")
        if existing.department_id != dept.id:
            log(f"  NOTE: {existing.email} is in a different department than the demo plan "
                f"({spec['dept']}); not changed")
        stats["users_existing"] += 1
        return existing

    used = roles.resolve(spec["role"])
    if used != spec["role"]:
        log(f"  ROLE FALLBACK: {spec['name']} requested {spec['role']} "
            f"-> using existing role {used}")
    user = User(
        **with_id(
            User,
            dict(
                name=spec["name"],
                email=spec["email"],
                password_hash=passwords.hash(spec["password"]),
                role=roles.to_stored(used),
                department_id=dept.id,
                active=True,
            ),
        )
    )
    db.add(user)
    db.flush()
    log(f"user CREATED      : {spec['name']} <{spec['email']}> role={used} dept={spec['dept']}")
    stats["users_created"] += 1
    return user


def ensure_resource(db, name, description, dept, owner, sensitivity, stats):
    existing = (
        db.query(Resource)
        .filter(Resource.name == name, Resource.department_id == dept.id)
        .first()
    )
    if existing:
        log(f"resource EXISTS   : {name} (sensitivity={existing.sensitivity}) - left unchanged")
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
    log(f"resource CREATED  : {name} [{sensitivity}] dept={dept.name} owner={owner.email}")
    stats["resources_created"] += 1
    return row


def ensure_grant(db, user, resource, granted_by, stats):
    rows = (
        db.query(AccessGrant)
        .filter(
            AccessGrant.user_id == user.id,
            AccessGrant.resource_id == resource.id,
            AccessGrant.permission == PERM_READ,
        )
        .all()
    )
    if any(g.revoked_at is None for g in rows):
        log(f"grant EXISTS      : {PERM_READ} {user.email} -> {resource.name}")
        stats["grants_existing"] += 1
        return
    if rows:
        log(f"grant WARNING     : only REVOKED {PERM_READ} grant(s) for {user.email} on "
            f"{resource.name}; not recreating (would override an admin revocation)")
        stats["grants_existing"] += 1
        return
    g = AccessGrant(
        **with_id(
            AccessGrant,
            dict(
                user_id=user.id,
                resource_id=resource.id,
                permission=PERM_READ,
                granted_by=granted_by.id,
            ),
        )
    )
    db.add(g)
    db.flush()
    log(f"grant CREATED     : {PERM_READ} {user.email} -> {resource.name}")
    stats["grants_created"] += 1


# ------------------------------------------------------------ verification

def decision_allowed(decision):
    val = getattr(decision, "allowed", None)
    if isinstance(val, bool):
        return val
    status = getattr(decision, "status", None)
    text = str(getattr(status, "value", status)).upper()
    if text == "ALLOW":
        return True
    if text == "DENY":
        return False
    return None


def decision_reason(decision) -> str:
    reason = getattr(decision, "reason", None)
    return str(getattr(reason, "name", reason))


def verify(db, users_by_email: dict, resources_by_key: dict) -> bool:
    log("verification via evaluate_access(..., 'read'):")
    ok = True
    for label, email, dept_key, res_name, expected in CHECKS:
        user = users_by_email.get(email.lower())
        res = resources_by_key.get((dept_key, res_name))
        if user is None or res is None:
            log(f"  [SKIP] {label}: user or resource not found ({email}, {res_name})")
            continue
        active = (
            db.query(AccessGrant)
            .filter(
                AccessGrant.user_id == user.id,
                AccessGrant.resource_id == res.id,
                AccessGrant.revoked_at.is_(None),
            )
            .all()
        )
        decision = evaluate_access(user, res, PERM_READ, active)
        allowed = decision_allowed(decision)
        shown = {True: "ALLOW", False: "DENY", None: "UNKNOWN"}[allowed]
        why = decision_reason(decision)
        if expected is None:
            log(f"  [INFO] {label}: actual={shown} reason={why}")
        elif allowed == expected:
            log(f"  [ok]   {label}: expected={'ALLOW' if expected else 'DENY'} "
                f"actual={shown} reason={why}")
        else:
            ok = False
            log(f"  [MISMATCH] {label}: expected={'ALLOW' if expected else 'DENY'} "
                f"actual={shown} reason={why}")
    return ok


# --------------------------------------------------------------------- main

def main() -> None:
    parser = argparse.ArgumentParser(description="Seed full GNOSIS demo data (idempotent).")
    parser.add_argument("--dry-run", action="store_true", help="do everything, then roll back")
    args = parser.parse_args()

    session_factory = getattr(dbmod, "SessionLocal", None)
    db = session_factory() if session_factory else next(dbmod.get_db())

    stats = dict(
        users_created=0, users_existing=0,
        departments_created=0, departments_existing=0,
        resources_created=0, resources_existing=0,
        grants_created=0, grants_existing=0,
    )

    try:
        # ---- roles ----
        roles = RoleResolver(db)
        log(f"role discovery: mode={roles.mode}; supported={sorted(roles.supported)}; "
            f"sources={roles.sources}")
        passwords = PasswordMaker()

        # ---- departments ----
        depts = {key: ensure_department(db, key, stats) for key in DEPARTMENTS}

        # ---- users (existing admin@ / employee@ are only looked up, never modified) ----
        users_by_email: dict[str, User] = {}
        for spec in USERS:
            users_by_email[spec["email"].lower()] = ensure_user(
                db, spec, depts[spec["dept"]], roles, passwords, stats
            )
        for email in (EXISTING_ADMIN_EMAIL, "employee@gnosis.com"):
            u = db.query(User).filter(func.lower(User.email) == email).first()
            if u:
                users_by_email[email] = u
            else:
                log(f"note: existing user {email} not found (skipped)")

        granted_by = users_by_email.get(EXISTING_ADMIN_EMAIL) or users_by_email["parth@gnosis.com"]

        # ---- resources ----
        resources_by_key: dict[tuple[str, str], Resource] = {}
        for name, dept_key, sensitivity, desc in RESOURCES:
            owner = users_by_email[OWNER_BY_DEPT[dept_key]]
            resources_by_key[(dept_key, name)] = ensure_resource(
                db, name, desc, depts[dept_key], owner, sensitivity, stats
            )

        # ---- grants ----
        for email, dept_key, res_name in GRANTS:
            user = users_by_email.get(email.lower())
            if user is None:
                log(f"grant SKIPPED     : user {email} not found")
                continue
            ensure_grant(db, user, resources_by_key[(dept_key, res_name)], granted_by, stats)

        # ---- verify BEFORE commit ----
        if not verify(db, users_by_email, resources_by_key):
            db.rollback()
            log(f"SUMMARY {stats}")
            fail("verification mismatch; nothing was committed")

        if args.dry_run:
            db.rollback()
            log("DRY RUN: verification passed, rolled back, nothing committed")
        else:
            db.commit()
            log("committed")

        log("SUMMARY")
        for key, value in stats.items():
            log(f"  {key}: {value}")
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