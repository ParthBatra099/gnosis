"""Verify revision 0007 using offline PostgreSQL DDL only: no migration connection."""

import importlib.util
from io import StringIO
from pathlib import Path
from unittest.mock import Mock

from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.script import ScriptDirectory
import pytest
from sqlalchemy import CheckConstraint, ForeignKeyConstraint
from sqlalchemy.schema import CreateIndex, CreateTable
from sqlalchemy.dialects import postgresql

from app.models import DepartmentAdminAssignment, User
from scripts.run_phase1_tests import EVIDENCE

BACKEND = Path(__file__).resolve().parents[1]
REVISION_FILE = BACKEND / "alembic/versions/0007_phase2_organization.py"


@pytest.fixture
def revision():
    spec = importlib.util.spec_from_file_location("organization_migration", REVISION_FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def offline_upgrade(revision, monkeypatch):
    output = StringIO()
    context = MigrationContext.configure(dialect_name="postgresql", opts={
        "as_sql": True, "output_buffer": output,
    })
    operations = Mock(wraps=Operations(context))
    monkeypatch.setattr(revision, "op", operations)
    before = EVIDENCE["connections"]
    revision.upgrade()
    assert EVIDENCE["connections"] == before
    return operations, output.getvalue()


def test_revision_extends_verified_repository_head(revision):
    assert revision.revision == "0007_phase2_organization"
    assert revision.down_revision == "0006_phase_4"
    config = Config()
    config.set_main_option("script_location", str(BACKEND / "alembic"))
    scripts = ScriptDirectory.from_config(config)
    # Unit 5 adds a descendant; 0007's verified identity dependency remains intact.
    assert scripts.get_heads() == ["0012"]
    assert scripts.get_revision("0009_phase2_org_management").down_revision == "0008_phase2_authentication"
    assert scripts.get_revision("0008_phase2_authentication").down_revision == revision.revision
    assert scripts.get_revision(revision.down_revision).down_revision == "0005_phase_3"


def test_upgrade_is_additive_without_backfill(offline_upgrade):
    operations, sql = offline_upgrade
    assert [call[0] for call in operations.mock_calls] == [
        "add_column", "create_check_constraint", "create_table",
        "create_index", "create_index", "create_index",
    ]
    table, column = operations.add_column.call_args.args
    assert table == "users" and column.name == "organization_role"
    assert column.nullable and column.default is None and column.server_default is None
    assert "ALTER TABLE users ADD COLUMN organization_role VARCHAR(50)" in sql
    assert "CREATE TYPE" not in sql  # portable string/check, not a PostgreSQL enum lifecycle
    for statement in sql.split(";"):
        assert not statement.lstrip().upper().startswith(("UPDATE ", "INSERT ", "DELETE ", "DROP ", "TRUNCATE "))


def test_role_check_matches_registered_model(offline_upgrade):
    operations, sql = offline_upgrade
    name, table, predicate = operations.create_check_constraint.call_args.args
    column = User.__table__.c.organization_role
    assert name == column.type.name == "ck_users_organization_role"
    assert table == "users"
    assert column.type.enums == ["SUPER_ADMIN", "DEPARTMENT_ADMIN", "EMPLOYEE"]
    assert column.type.validate_strings and not column.type.native_enum
    for role in column.type.enums:
        assert f"'{role}'" in predicate
    assert "'ADMIN'" not in predicate


def test_assignment_schema_and_indexes_match_registered_model(offline_upgrade):
    operations, sql = offline_upgrade
    args = operations.create_table.call_args.args
    assert args[0] == DepartmentAdminAssignment.__tablename__
    columns = {item.name: item for item in args[1:] if hasattr(item, "type")}
    model = DepartmentAdminAssignment.__table__
    assert columns.keys() == set(model.c.keys())
    dialect = postgresql.dialect()
    for name, column in columns.items():
        assert column.type.compile(dialect=dialect) == model.c[name].type.compile(dialect=dialect)
        assert column.nullable == model.c[name].nullable
        assert column.primary_key == model.c[name].primary_key
        assert (column.server_default is None) == (model.c[name].server_default is None)
    migration_checks = {item.name: str(item.sqltext) for item in args[1:]
                        if isinstance(item, CheckConstraint)}
    model_checks = {item.name: str(item.sqltext) for item in model.constraints
                    if isinstance(item, CheckConstraint)}
    assert migration_checks == model_checks

    def foreign_keys(constraints):
        return {(tuple(item.column_keys), tuple(element.target_fullname for element in item.elements),
                 item.ondelete) for item in constraints if isinstance(item, ForeignKeyConstraint)}

    assert foreign_keys(args[1:]) == foreign_keys(model.constraints)
    # Compile ORM DDL too, without an engine or database connection.
    model_ddl = str(CreateTable(model).compile(dialect=dialect))
    assert sql.count("ON DELETE RESTRICT") == model_ddl.count("ON DELETE RESTRICT") == 4
    for constraint in ("ck_department_admin_assignments_revocation_actor",
                       "ck_department_admin_assignments_revocation_time"):
        assert constraint in sql and constraint in model_ddl
    assert "TIMESTAMP WITH TIME ZONE" in sql
    assert "DEFAULT now()" in sql
    model_indexes = {index.name: index for index in model.indexes}
    assert {call.args[0] for call in operations.create_index.call_args_list} == set(model_indexes)
    for call in operations.create_index.call_args_list:
        name, table, fields = call.args
        index = model_indexes[name]
        assert table == model.name
        assert fields == [column.name for column in index.columns]
        assert call.kwargs.get("unique", False) == index.unique
        if index.unique:
            assert str(call.kwargs["postgresql_where"]) == "revoked_at IS NULL"
            assert str(call.kwargs["sqlite_where"]) == "revoked_at IS NULL"
            assert str(CreateIndex(index).compile(dialect=dialect)) + ";" in sql


def test_downgrade_refuses_to_destroy_identity_history(revision, monkeypatch):
    operations = Mock()
    monkeypatch.setattr(revision, "op", operations)
    with pytest.raises(RuntimeError, match="retain schema and history"):
        revision.downgrade()
    assert operations.mock_calls == []
