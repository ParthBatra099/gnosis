"""Preparation tests: mocked PG probes; all actual storage is isolated in-memory SQLite."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from sqlalchemy import create_engine, select, func, event, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.engine import URL
from sqlalchemy.orm import Session

from app.core.database import Base
from app.models import AuditEvent, Department, User, Resource
from app.models.data_disclosure import BusinessRecord, DataDisclosure
from app.services import demo_bootstrap as boot, demo_preparation as prep

REAL_VERIFY_TARGET = boot.verify_target
REAL_VERIFY_SERVER = prep.verify_server_address


@pytest.fixture
def setup(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    @event.listens_for(engine, "connect")
    def foreign_keys(connection, record):
        connection.execute("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(engine)
    manifest = boot.DemoManifest.model_validate_json((prep.BACKEND / "demo/identities.example.json").read_text())
    target = boot.DemoTarget(host="127.0.0.1", port=5432, database="fictional_demo",
        database_role="fictional_app", database_oid=123, instance_id=prep.uid(999), disposable=True)
    with Session(engine) as db, db.begin():
        db.add_all(Department(id=str(d.id), name=d.name) for d in manifest.departments)
        db.flush()
        db.add_all(User(id=str(u.id), name=u.name, email=u.email, password_hash="fixture-only-unused",
            role="EMPLOYEE", organization_role=u.organization_role, department_id=str(u.department_id), active=True)
            for u in manifest.users)
        db.flush()
        db.add(AuditEvent(id=boot.receipt_id(target), actor_id=None, action=boot.ACTION, outcome="ALLOW",
            context_data=dict(manifest_sha256=boot.digest(manifest), target_sha256=boot.digest(target),
                instance_id=str(target.instance_id), manifest_version=manifest.version, operator="FICTIONAL")))
    # Replace only PG-specific probes, not provenance, identity or dataset validation.
    monkeypatch.setattr(boot, "verify_target", lambda db, target: None)
    monkeypatch.setattr(prep, "verify_server_address", lambda *args: None)
    original = Session.execute
    def execute(self, statement, *args, **kwargs):
        if str(statement) == "SELECT pg_advisory_xact_lock(1196314447)":
            return None
        return original(self, statement, *args, **kwargs)
    monkeypatch.setattr(Session, "execute", execute)
    yield engine, manifest, target
    engine.dispose()


def load(setup, **kwargs):
    engine, manifest, target = setup
    with Session(engine) as db, db.begin():
        return prep.load_business_data(db, manifest, target, hostaddr="127.0.0.1", operator="FICTIONAL", **kwargs)


def test_dry_run_apply_duplicate_and_no_fake_evidence(setup):
    engine, _, _ = setup
    assert load(setup)["status"] == "DRY_RUN"
    with Session(engine) as db:
        assert db.scalar(select(func.count()).select_from(Resource)) == 0
    assert load(setup, apply=True)["status"] == "CREATED"
    assert load(setup, apply=True)["status"] == "VERIFIED_EXISTING"
    with Session(engine) as db:
        assert db.scalar(select(func.count()).select_from(Resource)) == 9
        assert db.scalar(select(func.count()).select_from(BusinessRecord)) == 54
        assert db.scalar(select(func.count()).select_from(DataDisclosure)) == 0
        events = db.scalars(select(AuditEvent)).all()
        assert len(events) == 2 and all(e.actor_id is None for e in events)


@pytest.mark.parametrize("kind", ["user", "department", "provenance", "resource", "record", "classification"])
def test_conflicts_fail_closed(setup, monkeypatch, kind):
    engine, _, _ = setup
    with Session(engine) as db, db.begin():
        if kind == "user":
            db.delete(db.get(User, prep.uid(4)))
        elif kind == "department":
            db.delete(db.get(Department, prep.uid(12)))
        elif kind == "provenance":
            db.scalar(select(AuditEvent)).context_data = {}
        elif kind == "resource":
            row = prep.dataset()[0][0] | {"name": "conflict"}
            db.add(Resource(**row))
        elif kind == "record":
            db.add(Resource(**prep.dataset()[0][0]))
            db.flush()
            db.add(BusinessRecord(**(prep.dataset()[1][0] | {"values": {"conflict": True}})))
    if kind == "classification":
        original = prep.dataset
        def bad():
            resources, records = original()
            records[0]["sensitivity"] = "CRITICAL"
            return resources, records
        monkeypatch.setattr(prep, "dataset", bad)
    with pytest.raises(ValueError):
        load(setup, apply=True)


def test_insertion_failure_rolls_back_all(setup, monkeypatch):
    engine, _, _ = setup
    original = Session.flush
    def fail(self, *a, **kw):
        if any(isinstance(row, BusinessRecord) for row in self.new):
            raise RuntimeError("simulated insertion failure")
        return original(self, *a, **kw)
    monkeypatch.setattr(Session, "flush", fail)
    with pytest.raises(RuntimeError):
        load(setup, apply=True)
    with Session(engine) as db:
        assert db.scalar(select(func.count()).select_from(Resource)) == 0
        assert db.scalar(select(func.count()).select_from(BusinessRecord)) == 0
        assert db.scalar(select(func.count()).select_from(AuditEvent)) == 1


def connection(target, *, row=None, nonempty=False, revision="0012", query=None):
    result = Mock()
    result.engine.url = URL.create("postgresql+psycopg", username=target.database_role,
        password="NEVER-PRINT-THIS", host=target.host, port=target.port, database=target.database, query=query or {})
    def execute(statement, *args):
        sql = str(statement)
        value = Mock()
        value.one.return_value = row or (target.database, target.database_role, target.schema_name,
            target.database_oid, "GNOSIS_LOCAL_DISPOSABLE_DEMO:" + str(target.instance_id),
            target.port, target.database_role)
        value.scalar_one.return_value = "127.0.0.1" if "inet_server_addr" in sql else nonempty
        value.scalars.return_value.all.return_value = [revision]
        return value
    result.execute.side_effect = execute
    return result


@pytest.mark.parametrize("field", range(7))
def test_every_migration_identity_component_checked(setup, field):
    target = setup[2]
    c = connection(target)
    row = list(c.execute("probe").one())
    row[field] = "mismatch"
    with pytest.raises(ValueError, match="identity/owner"):
        prep.migration_preflight(connection(target, row=tuple(row)), target, hostaddr="127.0.0.1")


def test_migration_empty_query_and_revision_guards(setup, monkeypatch):
    target = setup[2]
    for c in (connection(target, nonempty=True), connection(target, query={"options": "secret"})):
        with pytest.raises(ValueError):
            prep.migration_preflight(c, target, hostaddr="127.0.0.1")
    upgrade = Mock()
    monkeypatch.setattr(prep.command, "upgrade", upgrade)
    prep.migrate(connection(target), target, hostaddr="127.0.0.1")
    upgrade.assert_not_called()
    c = connection(target)
    prep.migrate(c, target, hostaddr="127.0.0.1", apply=True)
    config, revision = upgrade.call_args.args
    assert revision == "0012" and config.attributes["connection"] is c
    assert Path(config.get_main_option("script_location")).is_absolute()
    with pytest.raises(ValueError, match="revision"):
        prep.migrate(connection(target, revision="0011"), target, hostaddr="127.0.0.1", apply=True)


def test_loader_verification_failure_prevents_inserts(setup, monkeypatch):
    def reject(*args):
        raise ValueError("target/revision mismatch")
    monkeypatch.setattr(boot, "verify_target", reject)
    with pytest.raises(ValueError):
        load(setup, apply=True)


def test_cli_required_flags_and_descriptor(tmp_path, monkeypatch):
    import sys
    monkeypatch.syspath_prepend(str(prep.BACKEND / "scripts"))
    import prepare_local_demo as cli
    for args in ([], ["migrate"], ["migrate", "--local-demo", "--target", "missing"]):
        with pytest.raises(ValueError):
            cli.parser().parse_args(args)
    path = tmp_path / "target.json"
    for payload in ("{}", '{"DATABASE_URL":"NEVER-PRINT-THIS"}', "not json"):
        path.write_text(payload)
        with pytest.raises(ValueError):
            cli.read_descriptor(path)


def test_original_bootstrap_verifier_role_and_revision(setup):
    target = setup[2]
    verifier = REAL_VERIFY_TARGET
    for revision in ("0011", "0012"):
        c = connection(target, revision=revision)
        c.get_bind.return_value = SimpleNamespace(url=c.engine.url)
        original = c.execute.side_effect
        def execute(statement, *args):
            value = original(statement, *args)
            value.one.return_value = (*value.one.return_value[:6], "127.0.0.1/32", "gnosis_demo_owner")
            return value
        c.execute.side_effect = execute
        if revision == "0011":
            with pytest.raises(ValueError):
                verifier(c, target)
        else:
            verifier(c, target)


def test_real_verifier_rejects_wrong_role_without_leaking_password(setup):
    target = setup[2]
    c = connection(target)
    c.get_bind.return_value = SimpleNamespace(url=c.engine.url.set(username="wrong_role"))
    with pytest.raises(ValueError) as error:
        REAL_VERIFY_TARGET(c, target)
    assert "NEVER-PRINT-THIS" not in str(error.value)
    c.execute.assert_not_called()


def test_audit_flush_failure_rolls_back_dataset(setup, monkeypatch):
    engine, _, _ = setup
    original = Session.flush
    def fail(self, *a, **kw):
        if any(isinstance(row, AuditEvent) and row.action == "LOCAL_DEMO_DATA_PREPARED" for row in self.new):
            raise RuntimeError("simulated audit failure")
        return original(self, *a, **kw)
    monkeypatch.setattr(Session, "flush", fail)
    with pytest.raises(RuntimeError):
        load(setup, apply=True)
    with Session(engine) as db:
        assert db.scalar(select(func.count()).select_from(Resource)) == 0
        assert db.scalar(select(func.count()).select_from(BusinessRecord)) == 0


def test_descriptor_rejects_equal_roles_and_url_fields(tmp_path, monkeypatch, setup):
    monkeypatch.syspath_prepend(str(prep.BACKEND / "scripts"))
    import prepare_local_demo as cli
    import json
    target = setup[2]
    value = dict(target=target.model_dump(mode="json"), hostaddr="127.0.0.1", migration_owner_role="fictional_owner",
                 application_role=target.database_role)
    path = tmp_path / "descriptor.json"
    path.write_text(json.dumps(value))
    assert cli.read_descriptor(path).target == target
    for changes in ({"migration_owner_role": target.database_role},
                    {"application_role": "wrong"}, {"url": "postgresql://SECRET"}):
        path.write_text(json.dumps(value | changes))
        with pytest.raises(ValueError):
            cli.read_descriptor(path)


@pytest.mark.parametrize("relationship", ["owner", "resource"])
def test_invalid_dataset_foreign_keys_roll_back(setup, monkeypatch, relationship):
    engine, _, _ = setup
    original = prep.dataset
    def invalid():
        resources, records = original()
        if relationship == "owner":
            resources[-1]["owner_id"] = prep.uid(999)
        else:
            # Keep application classification validation satisfied; SQLite must
            # enforce the resource FK when flushing this deliberately invalid row.
            records[-1]["resource_id"] = prep.uid(999)
        return resources, records
    monkeypatch.setattr(prep, "dataset", invalid)
    if relationship == "owner":
        with pytest.raises(IntegrityError):
            load(setup, apply=True)
    else:
        with pytest.raises(ValueError, match="classification"):
            load(setup, apply=True)
        with Session(engine) as db, pytest.raises(IntegrityError), db.begin():
            db.add(BusinessRecord(id="invalid-reference", resource_id=prep.uid(999),
                                 category="SYNTHETIC", sensitivity="INTERNAL", values={}))
            db.flush()
    with Session(engine) as db:
        assert db.scalar(text("PRAGMA foreign_keys")) == 1
        assert db.scalar(select(func.count()).select_from(Resource)) == 0
        assert db.scalar(select(func.count()).select_from(BusinessRecord)) == 0
        assert db.scalar(select(func.count()).select_from(AuditEvent)) == 1


def test_record_fk_failure_after_resource_flush_rolls_back(setup, monkeypatch):
    engine, _, _ = setup
    original = Session.flush
    def invalid_reference(self, *args, **kwargs):
        rows = [row for row in self.new if isinstance(row, BusinessRecord)]
        if rows:
            rows[-1].resource_id = prep.uid(999)
        return original(self, *args, **kwargs)
    monkeypatch.setattr(Session, "flush", invalid_reference)
    with pytest.raises(IntegrityError):
        load(setup, apply=True)
    with Session(engine) as db:
        assert db.scalar(select(func.count()).select_from(Resource)) == 0
        assert db.scalar(select(func.count()).select_from(BusinessRecord)) == 0
        assert db.scalar(select(func.count()).select_from(AuditEvent)) == 1


@pytest.mark.parametrize("state", ["incomplete", "missing_receipt", "extra_record"])
def test_existing_dataset_integrity(setup, state):
    engine, _, target = setup
    load(setup, apply=True)
    with Session(engine) as db, db.begin():
        if state == "incomplete":
            db.delete(db.get(BusinessRecord, "demo-101-01"))
        elif state == "missing_receipt":
            db.delete(db.get(AuditEvent, str(prep.uuid5(target.instance_id, prep.DATASET))))
        else:
            db.add(BusinessRecord(id="unexpected", resource_id=prep.uid(101),
                category="SYNTHETIC", sensitivity="INTERNAL", values={}))
    with pytest.raises(ValueError):
        load(setup, apply=True)


def test_existing_grants_assignments_unchanged(setup):
    from app.models import AccessGrant, DepartmentAdminAssignment
    engine, _, _ = setup
    with Session(engine) as db, db.begin():
        row = prep.dataset()[0][0] | {"id": prep.uid(900), "name": "Unrelated fictional resource"}
        db.add(Resource(**row))
        db.flush()
        db.add(AccessGrant(id=prep.uid(901), user_id=prep.uid(4), resource_id=prep.uid(900),
            permission="read", granted_by=prep.uid(1)))
        db.add(DepartmentAdminAssignment(id=prep.uid(902), user_id=prep.uid(2),
            department_id=prep.uid(10), assigned_by=prep.uid(1)))
    def snapshot():
        with Session(engine) as db:
            return [db.execute(select(model.__table__)).all()
                    for model in (AccessGrant, DepartmentAdminAssignment)]
    before = snapshot()
    load(setup, apply=True)
    load(setup, apply=True)
    assert snapshot() == before


@pytest.fixture
def cli_case(setup, monkeypatch, tmp_path):
    import json
    import os
    monkeypatch.syspath_prepend(str(prep.BACKEND / "scripts"))
    import prepare_local_demo as cli
    for key in list(os.environ):
        if key.upper().startswith("PG"):
            monkeypatch.delenv(key)
    monkeypatch.setattr(cli, "install_demo_configuration", lambda: None)
    target = setup[2]
    path = tmp_path / "descriptor.json"
    path.write_text(json.dumps(dict(target=target.model_dump(mode="json"), hostaddr="127.0.0.1",
        migration_owner_role="fictional_owner", application_role=target.database_role)))
    args = ["migrate", "--local-demo", "--ack-disposable-demo", "--target", str(path)]
    return cli, args, target


@pytest.mark.parametrize("variable", ["PGHOSTADDR", "PGSERVICE", "PGSERVICEFILE", "PGSYSCONFDIR", "PGOPTIONS"])
def test_redirection_rejected_before_engine_or_password(cli_case, monkeypatch, capsys, variable):
    import sqlalchemy
    cli, args, _ = cli_case
    engine = Mock(side_effect=AssertionError("must not construct engine"))
    prompt = Mock(side_effect=AssertionError("must not accept password"))
    monkeypatch.setattr(sqlalchemy, "create_engine", engine)
    monkeypatch.setattr(cli, "password_prompt", prompt)
    monkeypatch.setenv(variable, "SECRET-REDIRECTION")
    assert cli.run(args) == 1
    engine.assert_not_called()
    prompt.assert_not_called()
    assert "SECRET-REDIRECTION" not in str(capsys.readouterr())


@pytest.mark.parametrize("failure", ["confirmation", "missing_file", "missing_hostaddr", "remote_hostaddr"])
def test_cli_input_failures_before_connection(cli_case, monkeypatch, failure):
    import sqlalchemy
    import json
    cli, args, _ = cli_case
    path = Path(args[-1])
    if failure == "confirmation":
        args += ["--apply-confirmation", "APPLY:wrong:instance"]
    elif failure == "missing_file":
        path.unlink()
    else:
        payload = json.loads(path.read_text())
        if failure == "missing_hostaddr":
            del payload["hostaddr"]
        else:
            payload["hostaddr"] = "192.0.2.1"
        path.write_text(json.dumps(payload))
    engine = Mock()
    monkeypatch.setattr(sqlalchemy, "create_engine", engine)
    assert cli.run(args) == 1
    engine.assert_not_called()


def test_getpass_warning_aborts_before_reading_credential(cli_case, monkeypatch, capsys):
    import sqlalchemy
    import warnings
    cli, args, _ = cli_case
    monkeypatch.setattr(cli.sys, "stdin", SimpleNamespace(isatty=lambda: True))
    accepted = []
    def insecure_prompt(prompt):
        warnings.warn("Echo is unavailable", cli.getpass.GetPassWarning)
        accepted.append("SECRET-CREDENTIAL")
        return "SECRET-CREDENTIAL"
    monkeypatch.setattr(cli.getpass, "getpass", insecure_prompt)
    engine = Mock()
    monkeypatch.setattr(sqlalchemy, "create_engine", engine)
    assert cli.run(args) == 1
    assert accepted == []
    engine.assert_not_called()
    assert "SECRET-CREDENTIAL" not in str(capsys.readouterr())


@pytest.mark.parametrize("command", ["migrate", "load-business-data"])
@pytest.mark.parametrize("commit_failure", [False, True])
def test_cli_commit_before_publication(cli_case, monkeypatch, capsys, command, commit_failure):
    from contextlib import contextmanager
    import sqlalchemy
    import sqlalchemy.orm
    cli, args, target = cli_case
    args[0] = command
    args += ["--apply-confirmation", f"APPLY:{command}:{target.instance_id}"]
    if command == "load-business-data":
        args += ["--manifest", str(prep.BACKEND / "demo/identities.example.json"), "--operator", "FICTIONAL"]
    engine = Mock()
    state = []
    @contextmanager
    def transaction():
        yield Mock()
        assert capsys.readouterr().out == ""
        if commit_failure:
            raise RuntimeError("SECRET-driver-error")
        state.append("committed")
    engine.begin = transaction
    session = Mock()
    session.__enter__ = Mock(return_value=session)
    session.__exit__ = Mock(return_value=False)
    session.begin = transaction
    monkeypatch.setattr(sqlalchemy.orm, "Session", lambda *a, **kw: session)
    captured = {}
    def create(*a, **kw):
        captured.update(kw)
        return engine
    monkeypatch.setattr(sqlalchemy, "create_engine", create)
    callbacks = []
    monkeypatch.setattr(sqlalchemy.event, "listens_for", lambda *a: lambda callback: callbacks.append(callback))
    monkeypatch.setattr(cli, "password_prompt", lambda: "SECRET-CREDENTIAL")
    monkeypatch.setattr(prep, "migrate", lambda *a, **kw: None)
    monkeypatch.setattr(prep, "load_business_data", lambda *a, **kw: {"status": "CREATED"})
    assert cli.run(args) == (1 if commit_failure else 0)
    output = capsys.readouterr()
    assert bool(output.out) == (not commit_failure)
    assert state == ([] if commit_failure else ["committed"])
    assert "SECRET" not in output.out + output.err
    assert captured["connect_args"]["hostaddr"] == "127.0.0.1"
    # Recheck on every actual DBAPI connect, including a late environment change.
    params = dict(host="127.0.0.1", hostaddr="127.0.0.1", port=target.port,
        dbname=target.database, user="fictional_owner" if command == "migrate" else target.database_role)
    callbacks[0](None, None, [], params)
    for key, value in (("hostaddr", "192.0.2.1"), ("host", "elsewhere"),
                       ("port", 1), ("dbname", "other"), ("user", "other"),
                       ("service", "unapproved"), ("servicefile", "unapproved")):
        with pytest.raises(ValueError, match="Connection parameters"):
            callbacks[0](None, None, [], params | {key: value})
    with pytest.raises(ValueError, match="Connection parameters"):
        callbacks[0](None, None, ["unapproved-dsn"], params)
    monkeypatch.setenv("PGHOSTADDR", "SECRET-LATE-REDIRECTION")
    with pytest.raises(ValueError):
        callbacks[0](None, None, [], params)


@pytest.mark.parametrize("address", [None, "192.0.2.1", "::1"])
def test_connected_server_mismatch_prevents_ddl(setup, monkeypatch, address):
    target = setup[2]
    c = connection(target)
    c.execute.side_effect = None
    c.execute.return_value.scalar_one.return_value = address
    monkeypatch.setattr(prep, "verify_server_address", REAL_VERIFY_SERVER)
    upgrade = Mock()
    monkeypatch.setattr(prep.command, "upgrade", upgrade)
    with pytest.raises(ValueError, match="server address"):
        prep.migrate(c, target, hostaddr="127.0.0.1", apply=True)
    upgrade.assert_not_called()


@pytest.mark.parametrize("migration_failure", [False, True])
def test_alembic_external_connection_transaction_ownership(setup, monkeypatch, migration_failure):
    import runpy
    from alembic.runtime.migration import MigrationContext
    import sqlalchemy
    engine = setup[0]
    with engine.connect() as connection:
        transaction = connection.begin()
        context_mock = Mock()
        context_mock.config = SimpleNamespace(config_file_name=None, attributes={"connection": connection},
                                             set_main_option=Mock())
        context_mock.is_offline_mode.return_value = False
        def configure(**kwargs):
            assert kwargs["connection"] is connection
            context_mock.migration_context = MigrationContext.configure(connection)
        context_mock.configure.side_effect = configure
        context_mock.begin_transaction.side_effect = lambda: context_mock.migration_context.begin_transaction()
        if migration_failure:
            context_mock.run_migrations.side_effect = RuntimeError("mocked migration failure")
        monkeypatch.setattr(__import__("alembic"), "context", context_mock)
        construct = Mock(side_effect=AssertionError("must reuse supplied connection"))
        monkeypatch.setattr(sqlalchemy, "engine_from_config", construct)
        commits = []
        event.listen(connection, "commit", lambda conn: commits.append(True))
        if migration_failure:
            with pytest.raises(RuntimeError, match="mocked migration"):
                runpy.run_path(str(prep.BACKEND / "alembic/env.py"))
        else:
            runpy.run_path(str(prep.BACKEND / "alembic/env.py"))
        assert connection.in_transaction() and transaction.is_active and not connection.closed
        assert commits == []
        construct.assert_not_called()
        context_mock.run_migrations.assert_called_once()
        transaction.rollback()


@pytest.mark.parametrize("host,hostaddr", [("127.0.0.1", "127.0.0.1"),
    ("localhost", "127.0.0.1"), ("::1", "::1"), ("localhost", "::1")])
def test_valid_pinned_server_address(setup, host, hostaddr):
    target = setup[2].model_copy(update={"host": host})
    c = connection(target)
    c.execute.side_effect = None
    c.execute.return_value.scalar_one.return_value = hostaddr
    REAL_VERIFY_SERVER(c, target, hostaddr)
    assert "pg_catalog.inet_server_addr()" in str(c.execute.call_args.args[0])


def test_missing_bootstrap_receipt_rejects_complete_identities(setup):
    engine, _, target = setup
    with Session(engine) as db, db.begin():
        db.delete(db.get(AuditEvent, boot.receipt_id(target)))
    with pytest.raises(ValueError, match="bootstrap provenance"):
        load(setup, apply=True)
    with Session(engine) as db:
        assert db.scalar(select(func.count()).select_from(User)) == 9
        assert db.scalar(select(func.count()).select_from(Resource)) == 0
        assert db.scalar(select(func.count()).select_from(BusinessRecord)) == 0


def test_matching_dataset_executes_no_dml(setup):
    engine, _, _ = setup
    load(setup, apply=True)
    statements = []
    def capture(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement.lstrip().split(None, 1)[0].upper())
    event.listen(engine, "before_cursor_execute", capture)
    try:
        assert load(setup, apply=True)["status"] == "VERIFIED_EXISTING"
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert not ({"INSERT", "UPDATE", "DELETE", "REPLACE"} & set(statements))


def test_non_terminal_prompt_rejects_before_getpass(cli_case, monkeypatch):
    cli, args, _ = cli_case
    monkeypatch.setattr(cli.sys, "stdin", SimpleNamespace(isatty=lambda: False))
    prompt = Mock(side_effect=AssertionError("must not request credentials"))
    monkeypatch.setattr(cli.getpass, "getpass", prompt)
    assert cli.run(args) == 1
    prompt.assert_not_called()


@pytest.mark.parametrize("stage", ["PASSWORD_INPUT", "ENGINE_CONSTRUCTION", "CONNECTION_ESTABLISHMENT",
    "TARGET_IDENTITY_VERIFICATION", "SCHEMA_VALIDATION", "ALEMBIC_GRAPH_VALIDATION",
    "DRY_RUN_TRANSACTION_COMPLETION"])
def test_failure_stage_tracks_real_dry_run_path(cli_case, monkeypatch, capsys, stage):
    import json
    import sqlalchemy
    from contextlib import contextmanager
    cli, args, target = cli_case
    secret = "synthetic-password postgresql://user:secret@host/private C:/private/secret.json SELECT private"
    def fail(*a, **kw):
        raise ValueError(secret)
    c = connection(target.model_copy(update={"database_role": "fictional_owner"}))
    original_execute = c.execute.side_effect
    def execute(statement, *a):
        if stage == "SCHEMA_VALIDATION" and "pg_depend" in str(statement):
            fail()
        return original_execute(statement, *a)
    c.execute.side_effect = execute
    @contextmanager
    def transaction():
        if stage == "CONNECTION_ESTABLISHMENT":
            fail()
        yield c
        if stage == "DRY_RUN_TRANSACTION_COMPLETION":
            fail()
    engine = Mock()
    engine.begin = transaction
    monkeypatch.setattr(sqlalchemy.event, "listens_for", lambda *a: lambda callback: callback)
    monkeypatch.setattr(cli, "password_prompt", fail if stage == "PASSWORD_INPUT" else lambda: secret)
    monkeypatch.setattr(sqlalchemy, "create_engine", fail if stage == "ENGINE_CONSTRUCTION" else lambda *a, **kw: engine)
    if stage == "TARGET_IDENTITY_VERIFICATION":
        monkeypatch.setattr(prep, "verify_server_address", fail)
    if stage == "ALEMBIC_GRAPH_VALIDATION":
        monkeypatch.setattr(prep.ScriptDirectory, "from_config", fail)
    upgrade = Mock(side_effect=AssertionError("dry-run must never execute migrations"))
    monkeypatch.setattr(prep.command, "upgrade", upgrade)
    assert cli.run(args) == 1
    output = capsys.readouterr()
    diagnostic = json.loads(output.err)
    assert set(diagnostic) == {"stage", "exception", "sqlstate", "category"}
    assert diagnostic["stage"] == stage
    assert diagnostic["exception"] == "ValueError"
    assert diagnostic["sqlstate"] is None
    assert output.out == ""
    assert all(value not in output.err for value in (secret, "synthetic-password", "postgresql://", "C:/private", "SELECT private"))
    upgrade.assert_not_called()


@pytest.mark.parametrize("wrapped", [False, True])
@pytest.mark.parametrize("driver_error,category", [("InvalidPassword", "AUTHENTICATION_FAILURE"),
    ("InsufficientPrivilege", "INSUFFICIENT_PRIVILEGE"), ("QueryCanceled", "DATABASE_WAIT_FAILURE"),
    ("ConnectionFailure", "CONNECTION_FAILURE"), ("UndefinedTable", "DATABASE_FAILURE")])
def test_registered_sqlstate_only_diagnostics(cli_case, monkeypatch, capsys, wrapped, driver_error, category):
    import json
    import psycopg
    from sqlalchemy.exc import OperationalError
    cli, args, _ = cli_case
    secret = "synthetic-password postgresql://user:password@host C:/secret/path SQL parameters"
    error = getattr(psycopg.errors, driver_error)(secret)
    sqlstate = error.sqlstate
    if wrapped:
        error = OperationalError("SELECT secret", {"password": secret}, error)
    def main(argv, *, progress):
        progress.set("CONNECTION_ESTABLISHMENT")
        raise error
    monkeypatch.setattr(cli, "main", main)
    assert cli.run(args) == 1
    output = capsys.readouterr()
    diagnostic = json.loads(output.err)
    assert diagnostic == dict(stage="CONNECTION_ESTABLISHMENT",
        exception="OperationalError" if wrapped else driver_error, sqlstate=sqlstate, category=category)
    assert output.out == "" and secret not in output.err and "SELECT secret" not in output.err


def test_custom_exception_attributes_and_name_are_not_disclosed(cli_case, monkeypatch, capsys):
    import json
    cli, args, _ = cli_case
    error_class = type("synthetic-password-postgresql://private/path", (Exception,), {})
    error = error_class("raw-secret-message")
    error.sqlstate = "secret-SQLSTATE"
    error.orig = RuntimeError("nested-private-message")
    error.__cause__ = ValueError("cause-private-message")
    def fail(argv, *, progress):
        raise error
    monkeypatch.setattr(cli, "main", fail)
    assert cli.run(args) == 1
    output = capsys.readouterr()
    assert json.loads(output.err) == dict(stage="PREPARATION", exception="Exception", sqlstate=None,
                                        category="INPUT_OR_CONFIGURATION_FAILURE")
    assert output.out == ""


def test_unregistered_driver_sqlstate_is_not_disclosed(cli_case):
    import psycopg
    cli = cli_case[0]
    error = psycopg.OperationalError("raw-private-message")
    error.sqlstate = "SECRT"
    result = cli.failure_diagnostic(cli.Progress(), error)
    assert result["sqlstate"] is None
    assert "raw-private" not in str(result) and "SECRT" not in str(result)


def test_bad_cli_arguments_are_not_echoed(cli_case, capsys):
    import json
    cli = cli_case[0]
    assert cli.run(["synthetic-password-postgresql://private/path"]) == 1
    output = capsys.readouterr()
    assert json.loads(output.err)["stage"] == "PREPARATION"
    assert "synthetic-password" not in output.err and output.out == ""


def test_password_interrupt_has_no_traceback(cli_case, monkeypatch, capsys):
    import json
    cli, args, _ = cli_case
    def interrupted():
        raise KeyboardInterrupt()
    monkeypatch.setattr(cli, "password_prompt", interrupted)
    assert cli.run(args) == 1
    output = capsys.readouterr()
    assert json.loads(output.err)["exception"] == "KeyboardInterrupt"
    assert json.loads(output.err)["stage"] == "PASSWORD_INPUT"
    assert "Traceback" not in output.err


def target_failure_output(cli_case, monkeypatch, capsys, c, target=None, hostaddr="127.0.0.1"):
    import json
    cli, args, default_target = cli_case
    def main(argv, *, progress):
        prep.migration_preflight(c, target or default_target, hostaddr=hostaddr, stage=progress.set)
    monkeypatch.setattr(cli, "main", main)
    assert cli.run(args) == 1
    output = capsys.readouterr()
    assert output.out == ""
    result = json.loads(output.err)
    assert result["stage"] == "TARGET_IDENTITY_VERIFICATION"
    assert result["exception"] == "TargetVerificationError"
    assert result["sqlstate"] is None
    assert all(fragment not in output.err for fragment in (
        "SYNTHETIC-PRIVATE", "postgresql://", "C:/private", "SELECT ", "Traceback"))
    return result


@pytest.mark.parametrize("component,value", [("drivername", "sqlite"), ("host", "192.0.2.1"),
    ("port", 1), ("database", "SYNTHETIC-PRIVATE-database"),
    ("username", "SYNTHETIC-PRIVATE-role"), ("query", {"service": "SYNTHETIC-PRIVATE-service"})])
def test_target_url_failure_category(cli_case, monkeypatch, capsys, component, value):
    c = connection(cli_case[2])
    c.engine.url = c.engine.url.set(**{component: value})
    result = target_failure_output(cli_case, monkeypatch, capsys, c)
    assert result["category"] == "CONNECTION_URL_VALIDATION_FAILURE"
    assert "field" not in result
    c.execute.assert_not_called()


@pytest.mark.parametrize("host,hostaddr", [("127.0.0.1", "192.0.2.1"), ("::1", "127.0.0.1")])
def test_target_loopback_failure_category(cli_case, monkeypatch, capsys, host, hostaddr):
    target = cli_case[2].model_copy(update={"host": host})
    c = connection(target)
    monkeypatch.setattr(prep, "verify_server_address", REAL_VERIFY_SERVER)
    result = target_failure_output(cli_case, monkeypatch, capsys, c, target, hostaddr)
    assert result["category"] == "LOOPBACK_VALIDATION_FAILURE"
    assert "field" not in result
    c.execute.assert_not_called()


def test_target_transaction_failure_category(cli_case, monkeypatch, capsys):
    c = connection(cli_case[2])
    c.in_transaction.return_value = False
    monkeypatch.setattr(prep, "verify_server_address", REAL_VERIFY_SERVER)
    result = target_failure_output(cli_case, monkeypatch, capsys, c)
    assert result["category"] == "ACTIVE_TRANSACTION_VALIDATION_FAILURE"
    assert "field" not in result
    c.execute.assert_not_called()


@pytest.mark.parametrize("address", [None, "127.0.0.2/32", "::1/128", "SYNTHETIC-PRIVATE-address"])
def test_target_server_address_failure_category(cli_case, monkeypatch, capsys, address):
    c = connection(cli_case[2])
    c.in_transaction.return_value = True
    c.execute.side_effect = None
    c.execute.return_value.scalar_one.return_value = address
    monkeypatch.setattr(prep, "verify_server_address", REAL_VERIFY_SERVER)
    result = target_failure_output(cli_case, monkeypatch, capsys, c)
    assert result["category"] == "SERVER_ADDRESS_VALIDATION_FAILURE"
    assert "field" not in result
    assert c.execute.call_count == 1


@pytest.mark.parametrize("index,field", enumerate(prep.TargetVerificationError.IDENTITY_FIELDS))
def test_each_identity_tuple_mismatch_reports_field_only(cli_case, monkeypatch, capsys, index, field):
    target = cli_case[2]
    row = list(connection(target).execute("fixture").one())
    row[index] = "SYNTHETIC-PRIVATE-value postgresql://private C:/private/file SELECT private"
    c = connection(target, row=tuple(row))
    c.in_transaction.return_value = True
    monkeypatch.setattr(prep, "verify_server_address", REAL_VERIFY_SERVER)
    result = target_failure_output(cli_case, monkeypatch, capsys, c)
    assert result == dict(stage="TARGET_IDENTITY_VERIFICATION", exception="TargetVerificationError",
        sqlstate=None, category="DATABASE_IDENTITY_VALIDATION_FAILURE", field=field)
    assert not any("pg_depend" in str(call.args[0]) for call in c.execute.call_args_list)


def test_multiple_identity_mismatches_report_first_field_only(cli_case, monkeypatch, capsys):
    c = connection(cli_case[2], row=("SYNTHETIC-PRIVATE",) * 7)
    result = target_failure_output(cli_case, monkeypatch, capsys, c)
    assert result["field"] == "database"
    assert result["category"] == "DATABASE_IDENTITY_VALIDATION_FAILURE"


def test_target_error_metadata_remains_allowlisted(cli_case):
    cli = cli_case[0]
    progress = cli.Progress()
    progress.set("TARGET_IDENTITY_VERIFICATION")
    error = prep.TargetVerificationError("DATABASE_IDENTITY_VALIDATION_FAILURE", "database")
    error.category = "SYNTHETIC-PRIVATE-category"
    error.field = "SYNTHETIC-PRIVATE-field"
    error.args = ("SYNTHETIC-PRIVATE-password postgresql://private",)
    result = cli.failure_diagnostic(progress, error)
    assert result["category"] == "TARGET_VERIFICATION_FAILURE"
    assert "field" not in result
    assert "SYNTHETIC-PRIVATE" not in str(result)
    with pytest.raises(ValueError):
        prep.TargetVerificationError("SYNTHETIC-PRIVATE-category")
    with pytest.raises(ValueError):
        prep.TargetVerificationError("DATABASE_IDENTITY_VALIDATION_FAILURE", "SYNTHETIC-PRIVATE-field")


def test_early_failure_diagnostic_does_not_import_business_configuration(cli_case, monkeypatch):
    import sys
    cli = cli_case[0]
    monkeypatch.delitem(sys.modules, "app.services.demo_preparation")
    monkeypatch.delitem(sys.modules, "app.core.config")
    result = cli.failure_diagnostic(cli.Progress(), ValueError("private-message"))
    assert result["category"] == "INPUT_OR_CONFIGURATION_FAILURE"
    assert "app.services.demo_preparation" not in sys.modules
    assert "app.core.config" not in sys.modules


@pytest.mark.parametrize("reported,hostaddr,accepted", [
    ("127.0.0.1/32", "127.0.0.1", True),
    ("127.0.0.1", "127.0.0.1", True),
    ("127.0.0.2/32", "127.0.0.1", False),
    ("::1/128", "127.0.0.1", False),
    ("malformed-private-address", "127.0.0.1", False),
    (None, "127.0.0.1", False),
    (b"127.0.0.1/32", "127.0.0.1", False),
    ("192.0.2.1/32", "127.0.0.1", False),
    ("127.0.0.1/24", "127.0.0.1", False),
    ("::1/128", "::1", True),
    ("::1", "::1", True),
    ("0:0:0:0:0:0:0:1/128", "::1", True),
    ("::1%private-zone/128", "::1", False),
    ("::ffff:127.0.0.1/128", "127.0.0.1", False),
    ("127.0.0.1/32", "::1", False),
])
def test_server_ip_comparison_preserves_exact_approved_address(setup, reported, hostaddr, accepted):
    target = setup[2].model_copy(update={"host": hostaddr})
    c = connection(target)
    c.in_transaction.return_value = True
    c.execute.side_effect = None
    c.execute.return_value.scalar_one.return_value = reported
    if accepted:
        REAL_VERIFY_SERVER(c, target, hostaddr)
    else:
        with pytest.raises(prep.TargetVerificationError) as error:
            REAL_VERIFY_SERVER(c, target, hostaddr)
        assert error.value.category == "SERVER_ADDRESS_VALIDATION_FAILURE"
        assert error.value.field is None
        assert str(error.value) == "Connected server address mismatch"
        assert error.value.__suppress_context__
    assert c.execute.call_count == 1


def test_ipv4_host_prefix_passes_complete_preflight(setup, monkeypatch):
    target = setup[2]
    c = connection(target)
    original = c.execute.side_effect
    def execute(statement, *args):
        result = original(statement, *args)
        if "inet_server_addr" in str(statement):
            result.scalar_one.return_value = "127.0.0.1/32"
        return result
    c.execute.side_effect = execute
    monkeypatch.setattr(prep, "verify_server_address", REAL_VERIFY_SERVER)
    stages = []
    prep.migration_preflight(c, target, hostaddr="127.0.0.1", stage=stages.append)
    assert stages == ["TARGET_IDENTITY_VERIFICATION", "SCHEMA_VALIDATION"]
    assert any("pg_depend" in str(call.args[0]) for call in c.execute.call_args_list)
