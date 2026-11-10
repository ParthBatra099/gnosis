import importlib.util
from io import StringIO
from pathlib import Path
from unittest.mock import Mock

import pytest
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.script import ScriptDirectory
from sqlalchemy import CheckConstraint, create_engine, inspect
from sqlalchemy.dialects import postgresql
from app.models import Base, MonitoringScope, RiskAssessment, SecurityEvent
from scripts.run_phase1_tests import EVIDENCE


def revision():
    path = Path(__file__).resolve().parents[1] / "alembic/versions/0012_behavioural_risk.py"
    spec = importlib.util.spec_from_file_location("behaviour_revision", path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def test_graph_and_offline_postgresql_parity(monkeypatch):
    config = Config()
    config.set_main_option("script_location", str(Path(__file__).resolve().parents[1] / "alembic"))
    graph = ScriptDirectory.from_config(config)
    assert graph.get_heads() == ["0012"]
    assert graph.get_revision("0012").down_revision == "0011"
    assert graph.get_revision("0011").down_revision == "0010_phase2_identity_validation"
    module = revision(); output = StringIO()
    operations = Mock(wraps=Operations(MigrationContext.configure(dialect_name="postgresql", opts={"as_sql": True, "output_buffer": output})))
    monkeypatch.setattr(module, "op", operations)
    before = EVIDENCE["connections"]
    module.upgrade()
    assert EVIDENCE["connections"] == before
    sql = output.getvalue().upper()
    assert not any(statement.strip().startswith(("UPDATE ", "DELETE ", "INSERT ", "DROP ", "TRUNCATE")) for statement in sql.split(";"))
    assert operations.create_unique_constraint.call_args.args == ("uq_security_events_episode_key", "security_events", ["episode_key"])
    for call in operations.add_column.call_args_list:
        table, column = call.args
        assert table == "security_events" and column.nullable
        assert column.type.compile(dialect=postgresql.dialect()) == SecurityEvent.__table__.c[column.name].type.compile(dialect=postgresql.dialect())
    for call, table in zip(operations.create_table.call_args_list, (RiskAssessment.__table__, MonitoringScope.__table__), strict=True):
        assert call.args[0] == table.name
        columns = {c.name: c for c in call.args[1:] if hasattr(c, "type")}
        assert set(columns) == set(table.c.keys())
        for name, column in columns.items():
            target = table.c[name]
            assert column.type.compile(dialect=postgresql.dialect()) == target.type.compile(dialect=postgresql.dialect())
            assert column.nullable == target.nullable and column.primary_key == target.primary_key
            assert {(f.target_fullname, f.ondelete) for f in column.foreign_keys} == {(f.target_fullname, f.ondelete) for f in target.foreign_keys}
        assert {c.name: str(c.sqltext) for c in call.args[1:] if isinstance(c, CheckConstraint)} == {c.name: str(c.sqltext) for c in table.constraints if isinstance(c, CheckConstraint)}
    with pytest.raises(RuntimeError, match="Preserve"):
        module.downgrade()


def test_additive_upgrade_on_memory_schema(monkeypatch):
    # PostgreSQL ALTER constraint is verified offline. SQLite batch support is not
    # substituted for production execution; exercise portable table creation here.
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=[t for t in Base.metadata.sorted_tables if t.name not in {"risk_assessments", "monitoring_scopes"}])
    with engine.begin() as connection:
        module = revision()
        operations = Operations(MigrationContext.configure(connection))
        proxy = Mock(wraps=operations)
        proxy.add_column = Mock()
        proxy.create_unique_constraint = Mock()
        monkeypatch.setattr(module, "op", proxy)
        module.upgrade()
        inspector = inspect(connection)
        for table in (RiskAssessment.__table__, MonitoringScope.__table__):
            assert {c["name"] for c in inspector.get_columns(table.name)} == set(table.c.keys())
            assert {i["name"] for i in inspector.get_indexes(table.name)} == {i.name for i in table.indexes}
    engine.dispose()
