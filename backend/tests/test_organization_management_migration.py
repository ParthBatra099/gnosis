"""Unit 7 DDL is compiled offline only; no migration database connection."""
import importlib.util
from io import StringIO
from pathlib import Path
from unittest.mock import Mock

from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.script import ScriptDirectory
import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateIndex

from app.models import Department
from scripts.run_phase1_tests import EVIDENCE


def revision():
    path = Path(__file__).resolve().parents[1] / "alembic/versions/0009_phase2_organization_management.py"
    spec = importlib.util.spec_from_file_location("organization_management_migration", path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def test_revision_is_additive_next_head_and_fits_alembic_version_column(monkeypatch):
    module = revision()
    backend = Path(__file__).resolve().parents[1]
    config = Config(); config.set_main_option("script_location", str(backend / "alembic"))
    scripts = ScriptDirectory.from_config(config)
    assert scripts.get_heads() == ["0010_phase2_identity_validation"]
    assert len(module.revision) <= 32
    assert module.down_revision == "0008_phase2_authentication"
    output = StringIO()
    context = MigrationContext.configure(dialect_name="postgresql", opts={"as_sql": True, "output_buffer": output})
    op = Mock(wraps=Operations(context)); monkeypatch.setattr(module, "op", op)
    before = EVIDENCE["connections"]
    module.upgrade()
    assert EVIDENCE["connections"] == before
    assert [call[0] for call in op.mock_calls] == ["add_column", "create_index"]
    table, column = op.add_column.call_args.args
    assert table == "departments" and column.name == "active"
    model = Department.__table__.c.active
    assert column.type.compile(dialect=postgresql.dialect()) == model.type.compile(dialect=postgresql.dialect())
    assert column.nullable == model.nullable == False
    assert str(column.server_default.arg) == str(model.server_default.arg) == "true"
    index = next(index for index in Department.__table__.indexes if index.name == "uq_departments_name_normalized")
    assert index.unique and op.create_index.call_args.kwargs["unique"]
    sql = output.getvalue()
    assert str(CreateIndex(index).compile(dialect=postgresql.dialect())) + ";" in sql
    assert "DEFAULT true NOT NULL" in sql
    for statement in sql.split(";"):
        assert not statement.strip().upper().startswith(("UPDATE", "DELETE", "INSERT", "DROP", "TRUNCATE"))


def test_downgrade_refuses_to_remove_lifecycle_history(monkeypatch):
    module = revision(); op = Mock(); monkeypatch.setattr(module, "op", op)
    with pytest.raises(RuntimeError, match="retain lifecycle and history"):
        module.downgrade()
    assert op.mock_calls == []
