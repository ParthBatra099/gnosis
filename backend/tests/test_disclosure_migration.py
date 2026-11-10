import importlib.util
from io import StringIO
from pathlib import Path
from unittest.mock import Mock

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import CheckConstraint, UniqueConstraint, create_engine, inspect
from sqlalchemy.dialects import postgresql
from app.models import Base, BusinessRecord, DataDisclosure
from scripts.run_phase1_tests import EVIDENCE


def revision():
    path = Path(__file__).resolve().parents[1] / "alembic/versions/0011_disclosure_evidence.py"
    spec = importlib.util.spec_from_file_location("disclosure_revision", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_offline_postgresql_additive_model_parity(monkeypatch):
    module = revision()
    output = StringIO()
    operations = Mock(wraps=Operations(MigrationContext.configure(
        dialect_name="postgresql", opts={"as_sql": True, "output_buffer": output})))
    monkeypatch.setattr(module, "op", operations)
    before = EVIDENCE["connections"]
    module.upgrade()
    assert EVIDENCE["connections"] == before
    assert module.revision == "0011" and module.down_revision == "0010_phase2_identity_validation"
    sql = output.getvalue().upper()
    assert not any(word in sql for word in ("INSERT INTO", "UPDATE ", "DELETE FROM", "DROP ", "ALTER TABLE"))
    for call, model in zip(operations.create_table.call_args_list, (BusinessRecord.__table__, DataDisclosure.__table__), strict=True):
        assert call.args[0] == model.name
        columns = {item.name: item for item in call.args[1:] if hasattr(item, "type")}
        assert set(columns) == set(model.c.keys())
        for name, column in columns.items():
            target = model.c[name]
            assert column.type.compile(dialect=postgresql.dialect()) == target.type.compile(dialect=postgresql.dialect())
            assert (column.nullable, column.primary_key) == (target.nullable, target.primary_key)
            assert {(fk.target_fullname, fk.ondelete) for fk in column.foreign_keys} == {(fk.target_fullname, fk.ondelete) for fk in target.foreign_keys}
        for kind in (CheckConstraint, UniqueConstraint):
            def signature(constraint):
                return (constraint.name, str(constraint.sqltext) if kind is CheckConstraint else tuple(constraint.columns.keys()))
            assert {signature(item) for item in call.args[1:] if isinstance(item, kind)} == {signature(item) for item in model.constraints if isinstance(item, kind)}
    expected = {index.name: (table.name, [c.name for c in index.columns])
                for table in (BusinessRecord.__table__, DataDisclosure.__table__) for index in table.indexes}
    assert {call.args[0]: (call.args[1], call.args[2]) for call in operations.create_index.call_args_list} == expected
    with pytest.raises(RuntimeError, match="preserved"):
        module.downgrade()


def test_upgrade_new_tables_on_disposable_memory_schema(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    tables = [t for t in Base.metadata.sorted_tables if t.name not in {"business_records", "data_disclosures"}]
    Base.metadata.create_all(engine, tables=tables)
    with engine.begin() as connection:
        module = revision()
        monkeypatch.setattr(module, "op", Operations(MigrationContext.configure(connection)))
        module.upgrade()
        inspector = inspect(connection)
        for model in (BusinessRecord.__table__, DataDisclosure.__table__):
            assert {c["name"] for c in inspector.get_columns(model.name)} == set(model.c.keys())
            assert {i["name"] for i in inspector.get_indexes(model.name)} == {i.name for i in model.indexes}
    engine.dispose()
