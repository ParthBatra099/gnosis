"""0010 predicates on memory fixtures; PostgreSQL DDL is offline only."""
import importlib.util
from io import StringIO
from pathlib import Path
from unittest.mock import Mock
import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.models import Base, Department, User
from tests.identity_transition_support import create_transition_schema


def revision():
    path = Path(__file__).resolve().parents[1] / "alembic/versions/0010_phase2_identity_validation.py"
    spec = importlib.util.spec_from_file_location("identity_validation_revision", path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def test_offline_validation_precedes_constraint_and_never_maps_or_deletes(monkeypatch):
    module = revision(); output = StringIO()
    operations = Mock(wraps=Operations(MigrationContext.configure(dialect_name="postgresql", opts={"as_sql": True, "output_buffer": output})))
    monkeypatch.setattr(module, "op", operations)
    module.upgrade(); sql = output.getvalue()
    assert module.revision == "0010_phase2_identity_validation" and len(module.revision) <= 32
    assert module.down_revision == "0009_phase2_org_management"
    assert "SHARE ROW EXCLUSIVE" in sql
    assert sql.index("RAISE EXCEPTION") < sql.index("SET NOT NULL")
    assert sql.count("RAISE EXCEPTION") == len(module.CHECKS)
    assert sql.count("END; $identity_validation$;") == len(module.CHECKS)
    assert "including inactive users" in sql
    assert not any(word in sql.upper() for word in ("UPDATE USERS", "INSERT INTO", "DELETE FROM", "DROP TABLE", "TRUNCATE"))
    assert operations.alter_column.call_args.kwargs["nullable"] is False
    with pytest.raises(RuntimeError, match="retain reviewed identities"): module.downgrade()


@pytest.mark.parametrize("active", [True, False])
def test_unresolved_legacy_admin_is_rejected_without_inference(active):
    engine = create_engine("sqlite:///:memory:"); create_transition_schema(engine)
    with Session(engine) as db, db.begin():
        db.add(Department(id="dept", name="Fixture")); db.flush()
        db.add(User(id="person", name="Person", email="person@example.invalid", role="ADMIN", password_hash="fixture", organization_role=None, department_id="dept", active=active))
    with engine.connect() as connection:
        assert connection.execute(text(revision().CHECKS[0][1])).first() is not None
        assert connection.execute(text("SELECT organization_role, role FROM users")).one() == (None, "ADMIN")
    engine.dispose()


@pytest.mark.parametrize("role", ["SUPER_ADMIN", "DEPARTMENT_ADMIN", "EMPLOYEE"])
def test_canonical_roles_pass_validation(role):
    engine = create_engine("sqlite:///:memory:"); Base.metadata.create_all(engine)
    with Session(engine) as db, db.begin():
        db.add(Department(id="dept", name="Fixture")); db.flush()
        db.add(User(id="person", name="Person", email="person@example.invalid", role="ADMIN", password_hash="fixture", organization_role=role, department_id="dept", active=False))
    with engine.connect() as connection:
        assert all(connection.execute(text(query)).first() is None for _, query in revision().CHECKS)
    engine.dispose()


def test_final_model_rejects_null_identity():
    engine = create_engine("sqlite:///:memory:"); Base.metadata.create_all(engine)
    assert User.__table__.c.organization_role.nullable is False
    with Session(engine) as db, db.begin(): db.add(Department(id="dept", name="Fixture"))
    with Session(engine) as db:
        with pytest.raises(IntegrityError), db.begin():
            db.add(User(name="Unmapped", email="unmapped@example.invalid", password_hash="fixture", role="ADMIN", organization_role=None, department_id="dept"))
    engine.dispose()


def test_active_assignment_role_checked_without_losing_revoked_history():
    engine = create_engine("sqlite:///:memory:"); Base.metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO departments (id,name,active) VALUES ('d','Fixture',true)"))
        connection.execute(text("INSERT INTO users (id,name,email,password_hash,role,organization_role,department_id,active) VALUES ('u','Fixture','fixture@example.invalid','fixture','ADMIN','EMPLOYEE','d',true)"))
        connection.execute(text("INSERT INTO department_admin_assignments (id,user_id,department_id,assigned_by,assigned_at) VALUES ('a','u','d','u','2026-01-01')"))
        query = revision().CHECKS[1][1]
        assert connection.execute(text(query)).first() is not None
        connection.execute(text("UPDATE department_admin_assignments SET revoked_at='2026-01-02', revoked_by='u' WHERE id='a'"))
        assert connection.execute(text(query)).first() is None
        assert connection.scalar(text("SELECT count(*) FROM department_admin_assignments")) == 1
    engine.dispose()


@pytest.mark.parametrize('index,corrupt', [
    (0, ["PRAGMA ignore_check_constraints=ON", "UPDATE users SET organization_role='ADMIN'"]),
    (2, ["UPDATE users SET department_id='missing'"]),
    (3, ["UPDATE department_admin_assignments SET assigned_by='missing'"]),
    (4, ["PRAGMA ignore_check_constraints=ON", "UPDATE department_admin_assignments SET revoked_by='u'"]),
    (5, ["DROP INDEX uq_department_admin_assignments_active_pair", "INSERT INTO department_admin_assignments (id,user_id,department_id,assigned_by,assigned_at) VALUES ('b','u','d','u','2026-01-01')"]),
])
def test_each_invalid_historical_snapshot_is_detected_without_repair(index, corrupt):
    # Deliberately damaged isolated snapshots test validation even when historical
    # constraints were bypassed. This engine is discarded after each case.
    engine = create_engine('sqlite:///:memory:'); create_transition_schema(engine)
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO departments (id,name,active) VALUES ('d','Fixture',true)"))
        connection.execute(text("INSERT INTO users (id,name,email,password_hash,role,organization_role,department_id,active) VALUES ('u','Fixture','fixture@example.invalid','fixture','ADMIN','DEPARTMENT_ADMIN','d',true)"))
        connection.execute(text("INSERT INTO department_admin_assignments (id,user_id,department_id,assigned_by,assigned_at) VALUES ('a','u','d','u','2026-01-01')"))
        for statement in corrupt: connection.execute(text(statement))
        assert connection.execute(text(revision().CHECKS[index][1])).first() is not None
        assert connection.scalar(text('SELECT count(*) FROM users')) == 1
    engine.dispose()
