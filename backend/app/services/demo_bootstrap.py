"""Operator-controlled fictional identity bootstrap. Never imported by normal startup.

No target is inferred from application settings. The caller owns the transaction.
"""
import hashlib
import json
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select, text

from app.core.constants import OrganizationRole
from app.core.security import hash_password
from app.models import AuditEvent, Department, User
from app.services.authentication_common import require_transaction

ACTION = "LOCAL_DEMO_BOOTSTRAPPED"


class DemoContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class DemoDepartment(DemoContract):
    id: UUID
    name: str = Field(min_length=1, max_length=100)


class DemoUser(DemoContract):
    id: UUID
    name: str = Field(min_length=1, max_length=100)
    email: str = Field(pattern=r"^demo-[a-z0-9._-]+@example\.com$", max_length=255)
    organization_role: OrganizationRole
    department_id: UUID


class DemoManifest(DemoContract):
    version: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    fictional: bool
    initial_super_admin: UUID
    departments: tuple[DemoDepartment, ...] = Field(min_length=1, max_length=20)
    users: tuple[DemoUser, ...] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def reviewed(self):
        if self.fictional is not True:
            raise ValueError("Only explicitly fictional identities are permitted")
        for values in ([str(d.id) for d in self.departments], [d.name.strip().casefold() for d in self.departments],
                       [str(u.id) for u in self.users], [u.email for u in self.users]):
            if len(set(values)) != len(values):
                raise ValueError("Duplicate manifest identity")
        departments = {d.id for d in self.departments}
        if any(u.department_id not in departments for u in self.users):
            raise ValueError("Unknown home department")
        supers = [u.id for u in self.users if u.organization_role == OrganizationRole.SUPER_ADMIN]
        if supers != [self.initial_super_admin]:
            raise ValueError("Select exactly one explicit initial Super Admin")
        return self


class DemoTarget(DemoContract):
    host: str = Field(pattern=r"^(127\.0\.0\.1|localhost|::1)$")
    port: int = Field(ge=1, le=65535)
    database: str = Field(pattern=r"^[A-Za-z0-9_-]{1,63}$")
    schema_name: str = "public"
    database_role: str = Field(pattern=r"^[A-Za-z0-9_-]{1,63}$")
    database_oid: int = Field(gt=0)
    instance_id: UUID
    disposable: bool

    @model_validator(mode="after")
    def local(self):
        if self.disposable is not True or self.schema_name != "public":
            raise ValueError("Explicit disposable public-schema target required")
        return self


def digest(value):
    return hashlib.sha256(json.dumps(value.model_dump(mode="json"), sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def receipt_id(target):
    return str(uuid5(target.instance_id, "GNOSIS:LOCAL_DEMO_BOOTSTRAP:v1"))


def verify_target(db, target):
    """Read-only target attestation; never creates the externally approved marker."""
    url = db.get_bind().url
    if (url.get_backend_name() != "postgresql" or url.host != target.host
            or (url.port or 5432) != target.port or url.database != target.database
            or url.username != target.database_role or url.query):
        raise ValueError("Explicit connection target mismatch")
    db.execute(text("SET LOCAL statement_timeout = '5s'"))
    db.execute(text("SET LOCAL lock_timeout = '3s'"))
    row = db.execute(text("SELECT current_database(), current_user, current_schema(), "
        "d.oid, shobj_description(d.oid, 'pg_database'), inet_server_port() "
        "FROM pg_database d WHERE d.datname=current_database()")).one()
    expected = (target.database, target.database_role, target.schema_name, target.database_oid,
                "GNOSIS_LOCAL_DISPOSABLE_DEMO:" + str(target.instance_id), target.port)
    if tuple(row) != expected:
        raise ValueError("Database identity/approval marker mismatch")
    if db.execute(text("SELECT version_num FROM public.alembic_version")).scalars().all() != ["0012"]:
        raise ValueError("Explicitly prepared migration head 0012 required")


def validate_receipt(db, manifest, target):
    receipts = db.scalars(select(AuditEvent).where(AuditEvent.action == ACTION)).all()
    if len(receipts) != 1:
        raise ValueError("Absent or ambiguous bootstrap provenance")
    event = receipts[0]
    expected = {"manifest_sha256": digest(manifest), "target_sha256": digest(target),
                "instance_id": str(target.instance_id), "manifest_version": manifest.version}
    if (event.id != receipt_id(target) or event.actor_id is not None or event.outcome != "ALLOW"
            or not isinstance(event.context_data, dict)
            or any(event.context_data.get(k) != v for k, v in expected.items())
            or not event.context_data.get("operator")):
        raise ValueError("Invalid bootstrap receipt")
    return event


def eligible(db, manifest, target, user_id):
    validate_receipt(db, manifest, target)
    declared = next((u for u in manifest.users if str(u.id) == user_id), None)
    user = db.get(User, user_id, populate_existing=True)
    if (declared is None or user is None or user.email != declared.email or user.name != declared.name
            or user.department_id != str(declared.department_id) or user.organization_role != declared.organization_role):
        raise ValueError("Identity is not in the approved bootstrap")
    return user


def verify_existing(db, manifest, target):
    validate_receipt(db, manifest, target)
    if set(db.scalars(select(User.id))) != {str(u.id) for u in manifest.users}:
        raise ValueError("Identity set differs from bootstrap")
    for u in manifest.users:
        row = eligible(db, manifest, target, str(u.id))
        if (row.name != u.name or row.organization_role != u.organization_role
                or row.department_id != str(u.department_id) or not row.active):
            raise ValueError("Bootstrap identity drift; never overwrite")
    actual = {(d.id, d.name) for d in db.scalars(select(Department))}
    if actual != {(str(d.id), d.name) for d in manifest.departments}:
        raise ValueError("Department drift")


def bootstrap(db, manifest, target, *, operator, passwords=None):
    """Dry-run unless per-run passwords supplied. No assignments/fake user actor.

    Call only after verify_target in the same transaction. CLI serializes bootstrap
    with a PostgreSQL advisory transaction lock. Tests use isolated SQLite only.
    """
    require_transaction(db)
    if not operator or len(operator) > 200:
        raise ValueError("Explicit operator provenance required")
    if any(db.scalar(select(model.id).limit(1)) is not None for model in (User, Department, AuditEvent)):
        raise ValueError("Non-empty target; use read-only verify-existing")
    if passwords is None:
        return
    if set(passwords) != {str(u.id) for u in manifest.users} or any(
            not isinstance(p, str) or not 12 <= len(p) <= 1024 for p in passwords.values()):
        raise ValueError("Explicit per-user passwords required (12–1024 characters)")
    db.add_all(Department(id=str(d.id), name=d.name, description="Fictional local demonstration")
               for d in manifest.departments)
    db.flush()
    db.add_all(User(id=str(u.id), name=u.name, email=u.email, password_hash=hash_password(passwords[str(u.id)]),
                    role="EMPLOYEE", organization_role=u.organization_role,
                    department_id=str(u.department_id), active=True) for u in manifest.users)
    db.flush()
    db.add(AuditEvent(id=receipt_id(target), actor_id=None, action=ACTION, outcome="ALLOW",
        reason="LOCAL_DEMO_OPERATOR_BOOTSTRAP", context_data={"manifest_sha256": digest(manifest),
        "target_sha256": digest(target), "instance_id": str(target.instance_id),
        "manifest_version": manifest.version, "operator": operator}))
    db.flush()
