"""Actual persisted-MFA boundary, fictional memory-only session inventories."""
import pytest
from sqlalchemy.orm import Session
from sqlalchemy import event
from app.models import AuditEvent, AuthenticationSession, UserAuthenticationState
from app.services.authentication_common import fingerprint
from app.services.authentication_transport import SESSION_COOKIE
from tests.authentication_support import session_token, browser_post
from tests.test_mfa_workflows import world


def login_as(world, subject):
    engine, client, _ = world
    with Session(engine) as db: token = session_token(db, subject)
    client.cookies.set(SESSION_COOKIE, token)
    return token


@pytest.mark.parametrize("actor", ["super", "admin", "employee"])
def test_each_role_can_list_and_revoke_only_own_session(world, actor):
    engine, client, _ = world
    token = login_as(world, actor)
    response = client.get('/auth/sessions')
    assert response.status_code == 200
    body = response.json(); assert body['total'] == 1
    row = body['items'][0]
    assert set(row) == {'session_ref','created_at','last_activity_at','expires_at','state','is_current'}
    assert row['is_current'] and row['state'] == 'ACTIVE'
    assert len(row['session_ref']) == 64 and token not in response.text
    with Session(engine) as db:
        session = db.query(AuthenticationSession).filter_by(user_id=actor).one()
        assert session.id not in response.text
        assert row['session_ref'] == fingerprint(session.id)
        generation = db.get(UserAuthenticationState, actor).security_generation
    result = browser_post(client, '/auth/sessions/' + row['session_ref'] + '/revoke', {'reason': 'Reviewed fixture revocation'})
    assert result.status_code == 204
    assert client.get('/auth/me').status_code == 401
    with Session(engine) as db:
        assert db.query(AuthenticationSession).filter_by(user_id=actor, revoked_at=None).count() == 0
        assert db.get(UserAuthenticationState, actor).security_generation == generation
        assert db.query(AuditEvent).filter_by(action='AUTH_SESSION_REVOKED').count() == 1


@pytest.mark.parametrize("actor", ["admin", "employee"])
def test_non_super_cannot_list_or_revoke_other_users_sessions(world, actor):
    engine, client, _ = world
    with Session(engine) as db:
        session_token(db, 'employee')
        target = fingerprint(db.query(AuthenticationSession).filter_by(user_id='employee').first().id)
    login_as(world, actor)
    assert client.get('/organization/employees/employee/sessions').status_code == 403
    assert browser_post(client, '/organization/employees/employee/sessions/' + target + '/revoke', {'reason': 'Reviewed fixture revocation'}).status_code == 403
    if actor != 'employee':
        assert browser_post(client, '/auth/sessions/' + target + '/revoke', {'reason': 'Reviewed fixture revocation'}).status_code == 404


def test_super_admin_targeted_revoke_and_atomic_audit_failure(world):
    engine, client, _ = world
    with Session(engine) as db: employee_token = session_token(db, 'employee')
    login_as(world, 'super')
    response = client.get('/organization/employees/employee/sessions?limit=1&offset=0')
    assert response.status_code == 200 and response.json()['limit'] == 1
    ref = response.json()['items'][0]['session_ref']
    path = '/organization/employees/employee/sessions/' + ref + '/revoke'
    def fail(mapper, connection, row):
        if row.action == 'AUTH_SESSION_REVOKED': raise RuntimeError('Injected strict audit failure')
    event.listen(AuditEvent, 'before_insert', fail)
    try: assert browser_post(client, path, {'reason': 'Reviewed fixture revocation'}).status_code == 503
    finally: event.remove(AuditEvent, 'before_insert', fail)
    with Session(engine) as db:
        assert db.query(AuthenticationSession).filter_by(user_id='employee', revoked_at=None).count() == 1
    assert browser_post(client, path, {'reason': 'Reviewed fixture revocation'}).status_code == 204
    client.cookies.set(SESSION_COOKIE, employee_token)
    assert client.get('/auth/me').status_code == 401


def test_sessions_require_mfa_csrf_and_bounded_pagination(world):
    _, client, _ = world
    assert client.get('/auth/sessions').status_code == 401
    login_as(world, 'employee')
    assert client.get('/auth/sessions?limit=101').status_code == 401
    assert client.post('/auth/sessions/' + 'a'*64 + '/revoke', json={'reason': 'Reviewed fixture revocation'}).status_code == 403
    assert browser_post(client, '/auth/sessions/' + 'a'*64 + '/revoke', {'reason': 'Reviewed fixture revocation'}).status_code == 404


def test_admin_revocation_audit_contains_actor_target_and_reason_but_no_raw_session(world):
    engine, client, _ = world
    with Session(engine) as db:
        session_token(db, 'employee')
        sid = db.query(AuthenticationSession.id).filter_by(user_id='employee').scalar()
    login_as(world, 'super')
    response = browser_post(client, '/organization/employees/employee/sessions/' + fingerprint(sid) + '/revoke', {'reason': 'Reviewed test revocation'})
    assert response.status_code == 204
    with Session(engine) as db:
        audit = db.query(AuditEvent).filter_by(action='AUTH_SESSION_REVOKED').one()
        assert audit.actor_id == 'super'
        assert audit.context_data['target_user_id'] == 'employee'
        assert audit.context_data['reason'] == 'Reviewed test revocation'
        assert sid not in str(audit.context_data)


def test_service_rechecks_actor_persisted_session_before_revoking_target(world):
    from fastapi import HTTPException
    from app.core.security import decode_access_token
    from app.services.authentication_sessions import revoke_session
    from app.services import session_management
    engine, _, _ = world
    with Session(engine) as db:
        actor_token = session_token(db, 'super')
        target_token = session_token(db, 'employee')
    actor_sid = decode_access_token(actor_token)['sid']
    target_sid = decode_access_token(target_token)['sid']
    with Session(engine) as db, db.begin():
        revoke_session(db, actor_sid, actor_user_id='super')
    with Session(engine) as source:
        with pytest.raises(HTTPException) as denied:
            session_management.revoke(source, 'super', 'employee', fingerprint(target_sid), 'Reviewed', actor_sid)
        assert denied.value.status_code == 401
    with Session(engine) as db:
        assert db.get(AuthenticationSession, target_sid).revoked_at is None
