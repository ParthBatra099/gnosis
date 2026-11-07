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
