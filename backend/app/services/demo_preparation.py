"""Explicit demo preparation only. Callers own commit/rollback; no normal startup imports."""
import hashlib
import ipaddress
import json
from pathlib import Path
from uuid import uuid5

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import select, text

from app.models import AuditEvent, Department, Resource, User
from app.models.data_disclosure import BusinessRecord
from app.services import demo_bootstrap as boot
from app.services.authentication_common import require_transaction

BACKEND = Path(__file__).resolve().parents[2]
DATASET = "fictional-business-v1"


class TargetVerificationError(ValueError):
    """Fixed diagnostic identifiers only; never retain observed identity values."""
    CATEGORIES = {
        "CONNECTION_URL_VALIDATION_FAILURE": "Migration connection target mismatch",
        "LOOPBACK_VALIDATION_FAILURE": "Explicit matching loopback hostaddr required",
        "ACTIVE_TRANSACTION_VALIDATION_FAILURE": "Caller-owned transaction required",
        "SERVER_ADDRESS_VALIDATION_FAILURE": "Connected server address mismatch",
        "DATABASE_IDENTITY_VALIDATION_FAILURE": "Migration identity/owner mismatch",
    }
    IDENTITY_FIELDS = ("database", "database_role", "schema_name", "database_oid",
                       "database_marker", "server_port", "database_owner")

    def __init__(self, category, field=None):
        if type(category) is not str or category not in self.CATEGORIES or (field is not None and (
                type(field) is not str or category != "DATABASE_IDENTITY_VALIDATION_FAILURE"
                or field not in self.IDENTITY_FIELDS)):
            raise ValueError("Unknown target verification diagnostic")
        super().__init__(self.CATEGORIES[category])
        self.category = category
        self.field = field


def verify_server_address(connection, target, hostaddr):
    if hostaddr not in ("127.0.0.1", "::1") or target.host not in ("localhost", hostaddr):
        raise TargetVerificationError("LOOPBACK_VALIDATION_FAILURE")
    if not connection.in_transaction():
        raise TargetVerificationError("ACTIVE_TRANSACTION_VALIDATION_FAILURE")
    reported = connection.execute(text("SELECT pg_catalog.inet_server_addr()::text")).scalar_one()
    try:
        if type(reported) is not str or "%" in reported:
            raise ValueError
        address = ipaddress.ip_interface(reported)
        approved = ipaddress.ip_address(hostaddr)
        # Accept a bare IP or its full host prefix, never a network, scoped IP,
        # alternate loopback address or an address from another family. No DNS.
        if (address.version != approved.version or not address.ip.is_loopback
                or address.ip != approved or address.network.prefixlen != address.max_prefixlen):
            raise ValueError
    except ValueError:
        raise TargetVerificationError("SERVER_ADDRESS_VALIDATION_FAILURE") from None


def migration_preflight(connection, target, *, hostaddr, stage=None):
    """No revision table is assumed. Verify identity, actual database owner and empty schema."""
    if stage is not None:
        stage("TARGET_IDENTITY_VERIFICATION")
    url = connection.engine.url
    if (url.get_backend_name() != "postgresql" or url.query or url.host != target.host
            or (url.port or 5432) != target.port or url.database != target.database
            or url.username != target.database_role):
        raise TargetVerificationError("CONNECTION_URL_VALIDATION_FAILURE")
    verify_server_address(connection, target, hostaddr)
    connection.execute(text("SET LOCAL statement_timeout = '5s'"))
    connection.execute(text("SET LOCAL lock_timeout = '3s'"))
    row = connection.execute(text("SELECT current_database(), current_user, current_schema(), d.oid, "
        "shobj_description(d.oid, 'pg_database'), inet_server_port(), pg_get_userbyid(d.datdba) "
        "FROM pg_database d WHERE d.datname=current_database()")).one()
    expected = (target.database, target.database_role, target.schema_name, target.database_oid,
                "GNOSIS_LOCAL_DISPOSABLE_DEMO:" + str(target.instance_id), target.port, target.database_role)
    actual = tuple(row)
    if actual != expected:
        field = next((name for name, observed, required in zip(
            TargetVerificationError.IDENTITY_FIELDS, actual, expected) if observed != required), None)
        raise TargetVerificationError("DATABASE_IDENTITY_VALIDATION_FAILURE", field)
    # Relations, functions, types and other schema-owned objects (including extensions).
    if stage is not None:
        stage("SCHEMA_VALIDATION")
    if connection.execute(text("SELECT EXISTS (SELECT 1 FROM pg_depend d "
        "JOIN pg_namespace n ON d.refclassid='pg_namespace'::regclass AND d.refobjid=n.oid "
        "WHERE n.nspname=:schema)") , {"schema": target.schema_name}).scalar_one():
        raise ValueError("Initial migration requires an empty schema")


def migrate(connection, target, *, hostaddr, apply=False, stage=None):
    migration_preflight(connection, target, hostaddr=hostaddr, stage=stage)
    if stage is not None:
        stage("ALEMBIC_GRAPH_VALIDATION")
    config = Config(str(BACKEND / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND / "alembic"))
    scripts = ScriptDirectory.from_config(config)
    if scripts.get_heads() != ["0012"]:
        raise ValueError("Reviewed migration graph head 0012 required")
    if apply:
        if stage is not None:
            stage("MIGRATION_EXECUTION")
        config.attributes["connection"] = connection
        command.upgrade(config, "0012")
        if stage is not None:
            stage("MIGRATION_REVISION_VERIFICATION")
        if connection.execute(text("SELECT version_num FROM public.alembic_version")).scalars().all() != ["0012"]:
            raise ValueError("Migration revision verification failed")


def uid(number):
    return "00000000-0000-0000-0000-" + str(number).zfill(12)


def dataset():
    resources, records = [], []
    labels = (("Planning", "Benefits", "Compensation Controls"),
              ("Pipeline", "Forecast", "Strategy Controls"),
              ("Stock", "Supplier Planning", "Controls"))
    for group, department in enumerate(("HR", "Sales", "Inventory")):
        for level, sensitivity in enumerate(("INTERNAL", "CONFIDENTIAL", "CRITICAL")):
            number = 101 + group * 3 + level
            resource = dict(id=uid(number), name=department + " " + labels[group][level],
                description="Fictional local evaluation data only", department_id=uid(10 + group),
                owner_id=uid(5 + group * 2), sensitivity=sensitivity)
            resources.append(resource)
            for ordinal in range(1, (12 if level == 0 else 3) + 1):
                records.append(dict(id=f"demo-{number}-{ordinal:02}", resource_id=resource["id"],
                    category=f"SYNTHETIC_{department.upper()}_{sensitivity}", sensitivity=sensitivity,
                    values={"synthetic": True, "reference": f"Fictional resource {number} item {ordinal:02}",
                            "quantity_units": ordinal * 10}))
    return resources, records


def load_business_data(db, manifest, target, *, hostaddr, operator, apply=False):
    require_transaction(db)
    verify_server_address(db.connection(), target, hostaddr)
    boot.verify_target(db, target)
    # Same serialization key as bootstrap. Validation and insertion share one transaction.
    db.execute(text("SELECT pg_advisory_xact_lock(1196314447)"))
    # Keep identity eligibility stable through insertion, using the existing ID order.
    db.scalars(select(User).order_by(User.id).with_for_update()).all()
    db.scalars(select(Department).order_by(Department.id).with_for_update()).all()
    boot.verify_existing(db, manifest, target)
    approved = boot.DemoManifest.model_validate_json((BACKEND / "demo/identities.example.json").read_text())
    if boot.digest(manifest) != boot.digest(approved):
        raise ValueError("Exact reviewed nine-identity manifest required")
    if not operator or len(operator) > 200:
        raise ValueError("Explicit operator required")
    if any(not d.active for d in db.scalars(select(Department))):
        raise ValueError("Inactive demo department")
    resources, records = dataset()
    classifications = {r["id"]: r["sensitivity"] for r in resources}
    if len(resources) != 9 or len(records) != 54 or any(
            r["sensitivity"] != classifications.get(r["resource_id"]) for r in records):
        raise ValueError("Dataset classification/count mismatch")
    payload_hash = hashlib.sha256(json.dumps([resources, records], sort_keys=True).encode()).hexdigest()
    receipt = dict(dataset=DATASET, dataset_sha256=payload_hash, manifest_sha256=boot.digest(manifest),
                   target_sha256=boot.digest(target), instance_id=str(target.instance_id), resources=9, records=54)
    event_id = str(uuid5(target.instance_id, DATASET))
    existing_event = db.get(AuditEvent, event_id)
    found = 0
    for model, rows in ((Resource, resources), (BusinessRecord, records)):
        for expected in rows:
            actual = db.get(model, expected["id"])
            if actual is not None:
                found += 1
                if any(getattr(actual, k) != v for k, v in expected.items()):
                    raise ValueError("Conflicting existing dataset object")
    actual_record_ids = set(db.scalars(select(BusinessRecord.id).where(
        BusinessRecord.resource_id.in_(classifications))))
    if actual_record_ids - {r["id"] for r in records}:
        raise ValueError("Unexpected records in demo resources")
    if found or existing_event:
        if (found != 63 or existing_event is None or existing_event.actor_id is not None
                or existing_event.action != "LOCAL_DEMO_DATA_PREPARED" or existing_event.outcome != "ALLOW"
                or not isinstance(existing_event.context_data, dict)
                or any(existing_event.context_data.get(k) != v for k, v in receipt.items())
                or not existing_event.context_data.get("operator")):
            raise ValueError("Partial dataset or invalid preparation receipt; never repair automatically")
        return dict(receipt, status="VERIFIED_EXISTING")
    if apply:
        db.add_all(Resource(**r) for r in resources)
        db.flush()
        db.add_all(BusinessRecord(**r) for r in records)
        db.add(AuditEvent(id=event_id, actor_id=None, action="LOCAL_DEMO_DATA_PREPARED", outcome="ALLOW",
            reason="LOCAL_DEMO_OPERATOR_DATA", context_data=dict(receipt, operator=operator)))
        db.flush()
    return dict(receipt, status="CREATED" if apply else "DRY_RUN")
