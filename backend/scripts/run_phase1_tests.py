"""Run backend tests with process-local, in-memory-only database safeguards."""

import os
from pathlib import Path
import sys

SAFE_DATABASE_URL = "sqlite:///:memory:"
EVIDENCE = {"engines": 0, "connections": 0, "blocked": 0}
_installed = False


def require_memory_url(url):
    from sqlalchemy.engine import make_url

    parsed = make_url(url)
    if (
        parsed.drivername != "sqlite"
        or parsed.database != ":memory:"
        or parsed.host or parsed.port or parsed.username or parsed.password
        or parsed.query
    ):
        EVIDENCE["blocked"] += 1
        raise RuntimeError("Test isolation: only sqlite:///:memory: is permitted")


def install_isolation():
    global _installed
    if _installed:
        return
    if "app.core.database" in sys.modules or "app.core.config" in sys.modules:
        raise RuntimeError("Test isolation must be installed before application imports")

    os.environ.update(
        DATABASE_URL=SAFE_DATABASE_URL,
        JWT_SECRET_KEY="gnosis-isolated-test-secret-not-for-production",
        DEBUG="false",
        ENVIRONMENT="test",
        PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
    )
    sys.dont_write_bytecode = True

    from sqlalchemy import event
    from sqlalchemy.engine import Engine, Dialect

    original_init = Engine.__init__

    def guarded_init(self, pool, dialect, url, logging_name=None, echo=None,
                     query_cache_size=500, execution_options=None, hide_parameters=False):
        # SQLAlchemy inspects these named constructor options during create_engine.
        require_memory_url(url)
        original_init(self, pool, dialect, url, logging_name=logging_name, echo=echo,
                      query_cache_size=query_cache_size, execution_options=execution_options,
                      hide_parameters=hide_parameters)
        EVIDENCE["engines"] += 1

    def guard_connection(dialect, connection_record, args, kwargs):
        # This executes before the DBAPI opens a database, including fixture engines.
        if (dialect.name != "sqlite" or list(args) != [":memory:"]
                or kwargs.get("uri") or "database" in kwargs):
            EVIDENCE["blocked"] += 1
            raise RuntimeError("Test isolation rejected a non-memory DBAPI connection")
        EVIDENCE["connections"] += 1

    Engine.__init__ = guarded_init
    event.listen(Dialect, "do_connect", guard_connection)
    _installed = True


def main():
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    # Share one guard instance with conftest and isolation tests.
    sys.modules["scripts.run_phase1_tests"] = sys.modules[__name__]
    install_isolation()
    import pytest

    try:
        return pytest.main(["-p", "no:cacheprovider", *sys.argv[1:]])
    finally:
        print(f"ISOLATION EVIDENCE: {EVIDENCE}; allowed database: {SAFE_DATABASE_URL}")


if __name__ == "__main__":
    raise SystemExit(main())
