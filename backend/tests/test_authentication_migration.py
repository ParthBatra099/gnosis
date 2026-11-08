"""Migration verification is offline PostgreSQL DDL only; no connection is made."""
import importlib.util
from io import StringIO
from pathlib import Path
from unittest.mock import Mock

from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.script import ScriptDirectory
import pytest
from sqlalchemy import CheckConstraint, ForeignKeyConstraint, PrimaryKeyConstraint, UniqueConstraint
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable

from app.models import (Base, UserAuthenticationState, MFACredential, AuthenticationChallenge,
                        AuthenticationSession, RecoveryCode, AuthenticationRateLimit)
from scripts.run_phase1_tests import EVIDENCE

BACKEND = Path(__file__).resolve().parents[1]
MODELS = [UserAuthenticationState, MFACredential, AuthenticationChallenge,
          AuthenticationSession, RecoveryCode, AuthenticationRateLimit]


@pytest.fixture
def revision():
    spec = importlib.util.spec_from_file_location("authentication_migration", BACKEND / "alembic/versions/0008_phase2_authentication.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def offline(revision, monkeypatch):
    output = StringIO()
    context = MigrationContext.configure(dialect_name="postgresql", opts={"as_sql": True, "output_buffer": output})
    operations = Mock(wraps=Operations(context))
    monkeypatch.setattr(revision, "op", operations)
    connections = EVIDENCE["connections"]
    revision.upgrade()
    assert EVIDENCE["connections"] == connections
    return operations, output.getvalue()


def test_authentication_revision_is_next_additive_head(revision, offline):
    config = Config()
    config.set_main_option("script_location", str(BACKEND / "alembic"))
    scripts = ScriptDirectory.from_config(config)
    assert revision.revision == "0008_phase2_authentication"
    assert revision.down_revision == "0007_phase2_organization"
    assert scripts.get_heads() == ["0010_phase2_identity_validation"]
    assert scripts.get_revision("0009_phase2_org_management").down_revision == revision.revision
    assert scripts.get_revision(revision.down_revision).down_revision == "0006_phase_4"
    operations, sql = offline
    assert {call[0] for call in operations.mock_calls} == {"create_table", "create_index"}
    assert {call.args[0] for call in operations.create_table.call_args_list} == {model.__tablename__ for model in MODELS}
    for statement in sql.split(";"):
        assert not statement.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE", "ALTER TABLE"))


def signature(constraint):
    if isinstance(constraint, CheckConstraint):
        return ("check", constraint.name, str(constraint.sqltext))
    if isinstance(constraint, ForeignKeyConstraint):
        return ("fk", tuple(constraint.column_keys), tuple(element.target_fullname for element in constraint.elements), constraint.ondelete)
    if isinstance(constraint, UniqueConstraint):
        return ("unique", tuple(column.name for column in constraint.columns))
    if isinstance(constraint, PrimaryKeyConstraint):
        return ("pk", tuple(column.name for column in constraint.columns))
    raise AssertionError(type(constraint))


@pytest.mark.parametrize("model", MODELS)
def test_migration_matches_registered_model_columns_constraints_indexes(model, offline):
    operations, sql = offline
    table = model.__table__
    assert Base.metadata.tables[table.name] is table
    call = next(call for call in operations.create_table.call_args_list if call.args[0] == table.name)
    # Operations(context) builds the migration table from the explicit arguments.
    migration_table = next(item.table for item in call.args[1:] if hasattr(item, "type"))
    dialect = postgresql.dialect()
    assert set(migration_table.c.keys()) == set(table.c.keys())
    for column in table.c:
        actual = migration_table.c[column.name]
        assert actual.type.compile(dialect=dialect) == column.type.compile(dialect=dialect)
        assert actual.nullable == column.nullable
        assert actual.primary_key == column.primary_key
        assert (None if actual.server_default is None else str(actual.server_default.arg)) == (None if column.server_default is None else str(column.server_default.arg))
    assert {signature(constraint) for constraint in migration_table.constraints} == {signature(constraint) for constraint in table.constraints}
    for constraint in table.foreign_key_constraints:
        assert constraint.ondelete == "RESTRICT"
    assert f"CREATE TABLE {table.name}" in sql
    assert "TIMESTAMP WITH TIME ZONE" in str(CreateTable(table).compile(dialect=dialect))
    model_indexes = {index.name: index for index in table.indexes}
    index_calls = [call for call in operations.create_index.call_args_list if call.args[1] == table.name]
    assert {call.args[0] for call in index_calls} == set(model_indexes)
    for call in index_calls:
        index = model_indexes[call.args[0]]
        assert call.args[2] == [column.name for column in index.columns]
        assert call.kwargs.get("unique", False) == index.unique
        for dialect_name in ("postgresql", "sqlite"):
            assert str(call.kwargs.get(f"{dialect_name}_where")) == str(index.dialect_options[dialect_name].get("where"))


def test_authentication_downgrade_refuses_history_destruction(revision, monkeypatch):
    operations = Mock()
    monkeypatch.setattr(revision, "op", operations)
    with pytest.raises(RuntimeError, match="retain credentials and history"):
        revision.downgrade()
    assert operations.mock_calls == []
