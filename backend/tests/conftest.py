"""Install database isolation before pytest imports application test modules."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.run_phase1_tests import install_isolation, require_memory_url

install_isolation()

from app.core.config import settings
from app.core.database import engine

require_memory_url(settings.DATABASE_URL)
require_memory_url(engine.url)


def pytest_report_header(config):
    return "GNOSIS isolation: application and fixture connections restricted to in-memory SQLite"


import pytest


@pytest.fixture(autouse=True)
def explicit_api_authentication_fixture(request, monkeypatch):
    """Only old consumer fixtures opt into non-browser, persisted-session transport."""
    modules = {"test_access_grants", "test_access_requests", "test_grant_lifecycle", "test_authorization",
               "test_console_and_incidents", "test_audit_and_detection", "test_ai_investigator",
               "test_governance_e2e", "test_auth", "test_administrative_consumers"}
    if (request.module.__name__.split(".")[-1] in modules
            or request.node.name == "test_security_state_and_challenges_not_created_by_existing_login"):
        from tests.authentication_support import configure
        configure(monkeypatch)
