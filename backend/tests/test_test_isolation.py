"""Safety checks to run before the application regression suite."""

import pytest
from sqlalchemy import create_engine, text

from scripts.run_phase1_tests import EVIDENCE, require_memory_url


@pytest.mark.parametrize("url", [
    "postgresql+psycopg://invalid:invalid@127.0.0.1/never_connect",
    "sqlite:///ordinary-project.db",
    "sqlite:///file:memory?mode=memory&uri=true",
    "sqlite://",
])
def test_unsafe_urls_are_rejected_without_connecting(url):
    with pytest.raises(RuntimeError, match="only sqlite"):
        require_memory_url(url)


def test_engine_guard_rejects_file_database_before_dbapi_connect():
    before = EVIDENCE["connections"]
    with pytest.raises(RuntimeError, match="only sqlite"):
        create_engine("sqlite:///must-not-exist.db")
    assert EVIDENCE["connections"] == before


def test_dbapi_guard_rejects_redirected_connection():
    engine = create_engine("sqlite:///:memory:", connect_args={"database": "must-not-exist.db"})
    try:
        with pytest.raises(RuntimeError, match="DBAPI connection"):
            engine.connect()
    finally:
        engine.dispose()


def test_application_and_disposable_database_are_memory_only():
    from app.core.database import engine as application_engine

    require_memory_url(application_engine.url)
    with application_engine.connect() as connection:
        assert connection.execute(text("PRAGMA database_list")).all() == [(0, "main", "")]

    disposable = create_engine("sqlite:///:memory:")
    try:
        with disposable.begin() as connection:
            connection.execute(text("CREATE TABLE isolation_probe (value INTEGER)"))
            connection.execute(text("INSERT INTO isolation_probe VALUES (1)"))
            assert connection.scalar(text("SELECT value FROM isolation_probe")) == 1
            assert connection.execute(text("PRAGMA database_list")).all() == [(0, "main", "")]
    finally:
        disposable.dispose()
