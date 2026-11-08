import ast
from pathlib import Path
import pytest
from sqlalchemy import text
from app.core.database import engine
from app.models import User
from app.services.assistant_service import AssistantService

BACKEND = Path(__file__).resolve().parents[1]


def test_application_engine_never_echoes_parameters_even_when_logger_is_enabled(caplog):
    assert engine.echo is False and engine.hide_parameters is True
    caplog.set_level('INFO', logger='sqlalchemy.engine.Engine')
    marker = 'FICTIONAL-SESSION-CAPABILITY-DO-NOT-LOG'
    with engine.connect() as connection:
        assert connection.scalar(text('SELECT :value'), {'value': marker}) == marker
    assert marker not in caplog.text


@pytest.mark.parametrize('script,entry', [('seed_demo_users.py','seed_demo_users'),('seed_demo_resources.py','main'),('seed_full_demo_data.py','main')])
def test_legacy_seed_entry_fails_before_opening_a_database(script, entry):
    tree = ast.parse((BACKEND/'scripts'/script).read_text(encoding='utf-8'))
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == entry)
    module = ast.Module(body=[function], type_ignores=[])
    namespace = {}
    exec(compile(module, str(BACKEND/'scripts'/script), 'exec'), namespace)
    with pytest.raises(SystemExit, match='Legacy demo seeding is disabled'):
        namespace[entry]()


@pytest.mark.parametrize('canonical', ['SUPER_ADMIN','DEPARTMENT_ADMIN','EMPLOYEE',None])
def test_assistant_profile_never_presents_legacy_admin_as_authority(canonical):
    user = User(id='fictional', name='Fixture', email='fixture@example.invalid', role='ADMIN', organization_role=canonical)
    result = AssistantService._handle_profile_query(user)
    assert (canonical or 'UNASSIGNED') in result.answer
    assert 'Role = ADMIN' not in result.answer
