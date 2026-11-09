"""Demo realm only: all database connections are launcher-guarded in-memory SQLite."""
from datetime import timedelta
from uuid import UUID

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.core.security import hash_password
from app.demo_app import create_demo_app
from app.models import (AuditEvent, AuthenticationChallenge, AuthenticationSession, MFACredential,
                        RecoveryCode, DepartmentAdminAssignment, Resource, User, UserAuthenticationState)
from app.services import demo_bootstrap as boot
from app.services.authentication_common import clock, fingerprint
from app.services.demo_authentication import MODE
from app.services.demo_transport import SESSION_COOKIE, CSRF_COOKIE
from app.main import create_app

ORIGIN = "https://localhost:5173"
PASSWORD = "Fictional-only-password-for-isolated-tests"


def uid(n):
    return str(UUID(int=n))


def contracts():
    manifest = boot.DemoManifest.model_validate(dict(version="fictional-test-v1", fictional=True,
        initial_super_admin=uid(1), departments=[dict(id=uid(10), name="HR"), dict(id=uid(11), name="Sales")],
        users=[dict(id=uid(i), name="Fictional " + role, email="demo-" + name + "@example.com",
                    organization_role=role, department_id=uid(10))
               for i, name, role in [(1, "super", "SUPER_ADMIN"), (2, "admin", "DEPARTMENT_ADMIN"), (3, "employee", "EMPLOYEE")]]))
    target = boot.DemoTarget.model_validate(dict(host="127.0.0.1", port=5432, database="fictional_demo",
        database_role="fictional_demo", database_oid=12345, instance_id=uid(99), disposable=True))
    return manifest, target


@pytest.fixture
def demo(monkeypatch):
    bind = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    @event.listens_for(bind, "connect")
    def foreign_keys(connection, record):
        connection.execute("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(bind)
    manifest, target = contracts()
    with Session(bind) as db, db.begin():
        boot.bootstrap(db, manifest, target, operator="FICTIONAL-TEST-OPERATOR",
                       passwords={str(u.id): PASSWORD for u in manifest.users})
    # Only the PG identity probe is replaced. Receipt/identity validation is real.
    # The production factory accepts no verifier injection or SQLite exemption.
    monkeypatch.setattr(boot, "verify_target", lambda db, target: None)
    app = create_demo_app(local_demo=True, acknowledge_password_only=True, bind=bind,
                          manifest=manifest, target=target, origins=[ORIGIN])
    with TestClient(app, base_url="https://localhost", client=("127.0.0.1", 50100)) as client:
        yield bind, app, client, manifest, target
    bind.dispose()


def post(client, path, payload=None):
    token = client.get("/auth/csrf", headers={"Origin": ORIGIN})
    assert token.status_code == 200, token.text
    return client.post(path, json=payload, headers={"Origin": ORIGIN, "X-CSRF-Token": token.json()["csrf_token"]})


def login(client, who="employee", password=PASSWORD):
    return post(client, "/auth/login", {"email": "demo-" + who + "@example.com", "password": password})


def test_explicit_activation_and_no_normal_demo_routes(demo, monkeypatch):
    bind, app, client, manifest, target = demo
    for flags in ({}, {"local_demo": True}, {"acknowledge_password_only": True}):
        with pytest.raises(ValueError, match="Explicit"):
            create_demo_app(bind=bind, manifest=manifest, target=target, origins=[ORIGIN], **flags)
    monkeypatch.setenv("ENVIRONMENT", "demo")
    monkeypatch.setenv("GNOSIS_DEMO_MODE", "true")
    normal = create_app()
    assert not hasattr(normal.state, "demo_sessions")
    assert "/auth/mfa/verify" in {r.path for r in normal.routes}
    assert "/auth/mfa/verify" not in {r.path for r in app.routes}
    assert not any(r.path.startswith("/ai") for r in app.routes)


@pytest.mark.parametrize("actor", ["employee", "admin", "super"])
def test_business_and_department_authority_unchanged(demo, actor):
    bind, app, client, _, _ = demo
    with Session(bind) as db, db.begin():
        db.add_all([Resource(id=uid(20), name="Fictional HR records", department_id=uid(10), owner_id=uid(3), sensitivity="INTERNAL"),
                    Resource(id=uid(21), name="Fictional Sales records", department_id=uid(11), owner_id=uid(2), sensitivity="CRITICAL")])
    assert login(client, actor).status_code == 200
    assert client.get("/resources/" + uid(20) + "/records").status_code == 200
    # Preserve existing ownership behavior, never grant Super Admin data access by role.
    assert client.get("/resources/" + uid(21) + "/records").status_code == (200 if actor == "admin" else 403)
    assert client.get("/monitoring/detections").status_code == (200 if actor == "super" else 403)
    if actor == "admin":
        with Session(bind) as db, db.begin():
            db.add(DepartmentAdminAssignment(user_id=uid(2), department_id=uid(10), assigned_by=uid(1)))
        # Assignment change invalidates the old demo session even without a generation bump.
        assert client.get("/monitoring/detections").status_code == 401
        assert login(client, actor).status_code == 200
        assert client.get("/monitoring/detections").status_code == 200


def test_logout_and_logout_all(demo):
    _, app, client, _, _ = demo
    assert login(client).status_code == 200
    assert post(client, "/auth/logout").status_code == 204
    assert client.get("/auth/me").status_code == 401
    assert login(client).status_code == 200
    assert login(client).status_code == 200
    assert post(client, "/auth/logout-all").status_code == 204
    assert all(s.revoked for s in app.state.demo_sessions.sessions.values())
    assert client.get("/auth/me").status_code == 401


def test_committed_revocation_denies_even_without_registry_publication(demo):
    bind, app, client, _, _ = demo
    assert login(client).status_code == 200
    registry = app.state.demo_sessions
    sid = client.cookies.get(SESSION_COOKIE)
    with registry.lock, Session(bind, autoflush=False) as db, db.begin():
        rows = registry.prepare_revocation(db, uid(3), uid(3), sid, session_ref=fingerprint(sid), reason="Fictional")
    assert not rows[0].revoked  # Simulate lost commit acknowledgement before memory update.
    assert client.get("/auth/me").status_code == 401


@pytest.mark.parametrize("mutation", ["legacy", "duplicate", "not-fictional", "unknown-department", "secret"])
def test_manifest_validation(mutation):
    manifest, target = contracts()
    value = manifest.model_dump(mode="json")
    if mutation == "legacy":
        value["users"][0]["organization_role"] = "ADMIN"
    elif mutation == "duplicate":
        value["users"].append(value["users"][0])
    elif mutation == "not-fictional":
        value["fictional"] = False
    elif mutation == "unknown-department":
        value["users"][0]["department_id"] = uid(999)
    else:
        value["users"][0]["password"] = "Must-not-be-accepted"
    with pytest.raises(ValueError):
        boot.DemoManifest.model_validate(value)


def test_launcher_flags_and_example_manifest():
    from scripts.run_local_demo import parser
    from pathlib import Path
    with pytest.raises(SystemExit):
        parser().parse_args(["serve", "--target", "fictional.json", "--manifest", "fictional.json"])
    with pytest.raises(SystemExit):
        parser().parse_args(["serve", "--local-demo", "--ack-password-only-demo", "--target", "fictional.json",
                             "--manifest", "fictional.json", "--workers", "2"])
    example = boot.DemoManifest.model_validate_json((Path(__file__).parents[1] / "demo" / "identities.example.json").read_text())
    assert len(example.users) == 9


def test_launcher_refuses_noninteractive_credentials(monkeypatch):
    from scripts.run_local_demo import main
    import sys
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    with pytest.raises(ValueError, match="Interactive terminal"):
        main(["bootstrap", "--local-demo", "--ack-password-only-demo", "--target", "nonexistent.json",
              "--manifest", "nonexistent.json"])


@pytest.mark.parametrize("base,peer", [("http://localhost", "127.0.0.1"),
    ("https://localhost", "192.0.2.1"), ("https://public.example.com", "127.0.0.1")])
def test_nonlocal_or_insecure_server_requests_rejected(demo, base, peer):
    _, app, _, _, _ = demo
    with TestClient(app, base_url=base, client=(peer, 50000)) as remote:
        assert remote.get("/health").status_code == 403


@pytest.mark.parametrize("mismatch", ["database", "role", "schema", "oid", "marker", "port", "revision"])
def test_postgres_identity_probe_contract_without_postgres(mismatch):
    """SQL response adapter only; does not claim live PostgreSQL verification."""
    from sqlalchemy.engine import URL
    _, target = contracts()
    row = [target.database, target.database_role, "public", target.database_oid,
           "GNOSIS_LOCAL_DISPOSABLE_DEMO:" + str(target.instance_id), target.port]
    if mismatch != "revision":
        row[["database", "role", "schema", "oid", "marker", "port"].index(mismatch)] = "WRONG"
    class Result:
        def one(self):
            return tuple(row)
        def scalars(self):
            return self
        def all(self):
            return ["WRONG"] if mismatch == "revision" else ["0012"]
    class Database:
        def get_bind(self):
            class Bind:
                url = URL.create("postgresql+psycopg", username=target.database_role,
                    host=target.host, port=target.port, database=target.database)
            return Bind()
        def execute(self, statement):
            return Result()
    with pytest.raises(ValueError):
        boot.verify_target(Database(), target)


@pytest.mark.parametrize("who", ["super", "admin", "employee"])
def test_login_profile_and_no_mfa_records(demo, who):
    bind, app, client, _, _ = demo
    result = login(client, who)
    assert result.status_code == 200, result.text
    assert result.json()["auth_mode"] == MODE
    assert "mfa" not in result.text.lower()
    profile = client.get("/auth/me")
    assert profile.status_code == 200
    assert profile.json()["organization_role"] == {"super": "SUPER_ADMIN", "admin": "DEPARTMENT_ADMIN", "employee": "EMPLOYEE"}[who]
    cookie = result.headers.get_list("set-cookie")
    assert all("Secure" in c and "HttpOnly" in c and "SameSite=strict" in c for c in cookie)
    with Session(bind) as db:
        for model in (AuthenticationSession, AuthenticationChallenge, MFACredential, RecoveryCode):
            assert db.query(model).count() == 0
        audit = db.query(AuditEvent).filter_by(action="DEMO_SESSION_CREATED").one()
        assert audit.context_data["auth_mode"] == MODE
        assert PASSWORD not in str(audit.context_data)


@pytest.mark.parametrize("failure", ["password", "inactive", "outsider", "receipt", "ambiguous", "target", "manifest"])
def test_failed_logins_fail_closed(demo, failure):
    bind, app, client, manifest, target = demo
    with Session(bind) as db, db.begin():
        if failure == "inactive":
            db.get(User, uid(3)).active = False
        elif failure == "outsider":
            db.add(User(id=uid(4), name="Fictional outsider", email="demo-outsider@example.com", password_hash=hash_password(PASSWORD),
                        organization_role="EMPLOYEE", department_id=uid(10), role="ADMIN", active=True))
        elif failure == "receipt":
            db.delete(db.get(AuditEvent, boot.receipt_id(target)))
        elif failure == "ambiguous":
            db.add(AuditEvent(action=boot.ACTION, outcome="ALLOW"))
        elif failure == "target":
            row = db.get(AuditEvent, boot.receipt_id(target))
            row.context_data = {**row.context_data, "target_sha256": "wrong"}
        elif failure == "manifest":
            row = db.get(AuditEvent, boot.receipt_id(target))
            row.context_data = {**row.context_data, "manifest_sha256": "wrong"}
    result = login(client, "outsider" if failure == "outsider" else "employee", "wrong" if failure == "password" else PASSWORD)
    assert result.status_code == 401, result.text
    assert not app.state.demo_sessions.sessions


@pytest.mark.parametrize("change", ["absolute", "idle", "run", "generation", "role", "name", "active", "assignment"])
def test_session_revalidates_current_state(demo, change):
    bind, app, client, _, _ = demo
    assert login(client).status_code == 200
    registry = app.state.demo_sessions
    session = next(iter(registry.sessions.values()))
    if change in {"absolute", "idle"}:
        setattr(session, "expires_at" if change == "absolute" else "idle_expires_at", clock() - timedelta(seconds=1))
    elif change == "run":
        registry.run_id = "different-run"
    else:
        with Session(bind) as db, db.begin():
            if change == "generation":
                db.get(UserAuthenticationState, uid(3)).security_generation += 1
            elif change == "assignment":
                db.add(DepartmentAdminAssignment(user_id=uid(3), department_id=uid(11), assigned_by=uid(1)))
            else:
                setattr(db.get(User, uid(3)), {"role": "organization_role", "name": "name", "active": "active"}[change],
                        {"role": "SUPER_ADMIN", "name": "Changed", "active": False}[change])
    assert client.get("/auth/me").status_code == 401


def test_revocation_and_restart(demo):
    bind, app, client, manifest, target = demo
    assert login(client).status_code == 200
    sessions = client.get("/auth/sessions").json()
    ref = sessions["items"][0]["session_ref"]
    assert post(client, "/auth/sessions/" + ref + "/revoke", {"reason": "Fictional evaluation"}).status_code == 204
    assert client.get("/auth/me").status_code == 401
    assert login(client).status_code == 200
    sid = client.cookies.get(SESSION_COOKIE)
    other = create_demo_app(local_demo=True, acknowledge_password_only=True, bind=bind,
                            manifest=manifest, target=target, origins=[ORIGIN])
    with TestClient(other, base_url="https://localhost", client=("127.0.0.1", 50101)) as restarted:
        restarted.cookies.set(SESSION_COOKIE, sid)
        assert restarted.get("/auth/me").status_code == 401


@pytest.mark.parametrize("actor,status", [("employee", 403), ("admin", 403), ("super", 200)])
def test_cross_user_session_scope(demo, actor, status):
    bind, app, client, _, _ = demo
    assert login(client).status_code == 200
    ref = client.get("/auth/sessions").json()["items"][0]["session_ref"]
    assert login(client, actor).status_code == 200
    route = "/organization/employees/" + uid(3) + "/sessions"
    assert client.get(route).status_code == status
    result = post(client, route + "/" + ref + "/revoke", {"reason": "Fictional review"})
    assert result.status_code == (204 if status == 200 else 403)


@pytest.mark.parametrize("operation", ["login", "revoke"])
def test_audit_failure_never_reports_success(demo, operation):
    bind, app, client, _, _ = demo
    if operation == "revoke":
        assert login(client).status_code == 200
        ref = client.get("/auth/sessions").json()["items"][0]["session_ref"]
    def fail(mapper, connection, row):
        if row.action.startswith("DEMO_"):
            raise RuntimeError("Fictional audit failure")
    event.listen(AuditEvent, "before_insert", fail)
    try:
        result = login(client) if operation == "login" else post(client, "/auth/sessions/" + ref + "/revoke", {"reason": "Fictional"})
        assert result.status_code == 503
        if operation == "login":
            assert not app.state.demo_sessions.sessions
        else:
            assert client.get("/auth/me").status_code == 200
    finally:
        event.remove(AuditEvent, "before_insert", fail)


def test_rate_csrf_transport_and_no_secret_echo(demo):
    _, app, client, _, _ = demo
    assert client.post("/auth/login", json={"password": PASSWORD}).status_code in {403, 422}
    response = post(client, "/auth/login", {"password": PASSWORD})
    assert PASSWORD not in response.text
    assert client.get("/health", headers={"X-Forwarded-Proto": "https"}).status_code == 403
    assert client.get("/auth/csrf", headers={"Origin": "https://evil.example.com"}).status_code == 403
    for _ in range(5):
        assert login(client, password="wrong").status_code == 401
    assert login(client).status_code == 429


def test_mutually_exclusive_cookies(demo):
    bind, app, client, _, _ = demo
    from app.services.authentication_transport import SESSION_COOKIE as NORMAL_COOKIE
    from tests.authentication_support import configure, session_token
    # A normal token cannot authenticate the demo, in either cookie namespace.
    from pytest import MonkeyPatch
    with MonkeyPatch.context() as patch:
        configure(patch)
        with Session(bind) as db:
            token = session_token(db, uid(3))
        client.cookies.set(NORMAL_COOKIE, token)
        client.cookies.set(SESSION_COOKIE, token)
        assert client.get("/auth/me").status_code == 401
        client.cookies.clear()
        assert login(client).status_code == 200
        sid = client.cookies.get(SESSION_COOKIE)
        normal = create_app()
        from app.core.database import get_db
        def database():
            with Session(bind) as db:
                yield db
        normal.dependency_overrides[get_db] = database
        with TestClient(normal, base_url="https://localhost", client=("127.0.0.1", 50200)) as ordinary:
            ordinary.cookies.set(SESSION_COOKIE, sid)
            ordinary.cookies.set(NORMAL_COOKIE, sid)
            assert ordinary.get("/auth/me").status_code == 401


def test_bootstrap_dry_run_atomic_receipt_and_no_overwrite():
    bind = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind)
    manifest, target = contracts()
    with Session(bind) as db, db.begin():
        boot.bootstrap(db, manifest, target, operator="FICTIONAL")
        assert db.query(User).count() == 0
    def fail(*args):
        raise RuntimeError("Fictional failure")
    event.listen(AuditEvent, "before_insert", fail)
    try:
        with pytest.raises(RuntimeError), Session(bind) as db, db.begin():
            boot.bootstrap(db, manifest, target, operator="FICTIONAL", passwords={str(u.id): PASSWORD for u in manifest.users})
    finally:
        event.remove(AuditEvent, "before_insert", fail)
    with Session(bind) as db, db.begin():
        assert db.query(User).count() == db.query(AuditEvent).count() == 0
        boot.bootstrap(db, manifest, target, operator="FICTIONAL", passwords={str(u.id): PASSWORD for u in manifest.users})
    with Session(bind) as db, db.begin():
        boot.verify_existing(db, manifest, target)
        with pytest.raises(ValueError, match="Non-empty"):
            boot.bootstrap(db, manifest, target, operator="FICTIONAL")
        with pytest.raises(ValueError, match="target mismatch"):
            boot.verify_target(db, target)
    bind.dispose()


@pytest.mark.parametrize("change", ["oid", "missing-marker", "changed-marker", "schema", "role", "revision", "unavailable"])
@pytest.mark.parametrize("path", ["/auth/me", "/auth/login", "/auth/sessions"])
def test_live_target_failure_permanently_invalidates_run(demo, monkeypatch, change, path):
    _, app, client, _, _ = demo
    assert login(client).status_code == 200
    token = client.get("/auth/csrf", headers={"Origin": ORIGIN}).json()["csrf_token"]
    calls = []
    def changed_target(db, target):
        assert db.in_transaction()
        calls.append(db.connection())
        if change == "unavailable":
            raise OSError("Fictional connection failure")
        raise ValueError("Fictional target mismatch: " + change)
    monkeypatch.setattr(boot, "verify_target", changed_target)
    if path == "/auth/login":
        result = client.post(path, json={"email": "demo-employee@example.com", "password": PASSWORD},
            headers={"Origin": ORIGIN, "X-CSRF-Token": token})
    else:
        result = client.get(path)
    assert result.status_code in {401, 503}
    assert app.state.demo_sessions.invalidated
    assert not app.state.demo_sessions.sessions
    count = len(calls)
    monkeypatch.setattr(boot, "verify_target", lambda db, target: calls.append("must-not-retry"))
    for endpoint in ("/auth/me", "/auth/csrf", "/auth/sessions", "/monitoring/detections"):
        assert client.get(endpoint, headers={"Origin": ORIGIN}).status_code == 503
    assert len(calls) == count


def test_target_probe_uses_authentication_audit_connection(demo, monkeypatch):
    _, _, client, _, _ = demo
    checked = set()
    def check(db, target):
        assert db.in_transaction()
        checked.add(db.connection())
    def audit_connection(mapper, connection, row):
        if row.action == "DEMO_SESSION_CREATED":
            assert connection in checked
    monkeypatch.setattr(boot, "verify_target", check)
    event.listen(AuditEvent, "before_insert", audit_connection)
    try:
        assert login(client).status_code == 200
    finally:
        event.remove(AuditEvent, "before_insert", audit_connection)


@pytest.mark.parametrize("action", ["login", "activity", "revoke"])
def test_commit_failure_does_not_publish_security_state(demo, monkeypatch, action):
    bind, app, client, _, _ = demo
    from app.services import demo_authentication as service
    from app.services.authentication_common import AuthenticationError
    registry = app.state.demo_sessions
    sid = None
    if action != "login":
        assert login(client).status_code == 200
        sid = client.cookies.get(SESSION_COOKIE)
        before = registry.snapshot(sid)
        monkeypatch.setattr(service, "clock", lambda: before.created_at + timedelta(seconds=60))
    def fail(db):
        if db.info.get("fictional_commit_failure"):
            raise RuntimeError("Fictional commit failure")
    event.listen(Session, "before_commit", fail)
    try:
        with pytest.raises(RuntimeError), registry.operation(bind, uid(3)) as db:
            db.info["fictional_commit_failure"] = True
            if action == "login":
                registry.prepare_login(db, "demo-employee@example.com", PASSWORD)
            elif action == "activity":
                registry.validate(db, sid, touch=True)
            else:
                registry.prepare_revocation(db, uid(3), uid(3), sid, session_ref=fingerprint(sid), reason="Fictional")
    finally:
        event.remove(Session, "before_commit", fail)
    if action == "login":
        assert not registry.sessions
    else:
        after = registry.snapshot(sid)
        assert after.last_activity_at == before.last_activity_at
        assert after.idle_expires_at == before.idle_expires_at
        assert after.expires_at == before.expires_at
        assert not after.revoked
        with registry.operation(bind, uid(3)) as db:
            registry.validate(db, sid)
    with Session(bind) as db:
        assert db.query(AuditEvent).filter_by(action="DEMO_SESSION_REVOKED").count() == 0
        assert db.query(AuditEvent).filter_by(action="DEMO_SESSION_CREATED").count() == (0 if action == "login" else 1)


def test_activity_published_only_after_commit(demo, monkeypatch):
    bind, app, client, _, _ = demo
    from app.services import demo_authentication as service
    assert login(client).status_code == 200
    registry = app.state.demo_sessions
    sid = client.cookies.get(SESSION_COOKIE)
    before = registry.snapshot(sid)
    later = before.created_at + timedelta(seconds=60)
    monkeypatch.setattr(service, "clock", lambda: later)
    with registry.operation(bind, uid(3)) as db:
        registry.validate(db, sid, touch=True)
        assert registry.snapshot(sid).idle_expires_at == before.idle_expires_at
    after = registry.snapshot(sid)
    assert after.last_activity_at == later
    assert after.idle_expires_at == later + timedelta(seconds=registry.idle_seconds)
    assert after.expires_at == before.expires_at


@pytest.mark.parametrize("mutation", ["revoke", "identity"])
def test_concurrent_login_and_security_mutation_are_serialized_without_global_lock(demo, monkeypatch, mutation):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from app.services import demo_authentication as service
    from app.services.authentication_common import AuthenticationError
    from app.services.authentication_sessions import invalidate_user_sessions
    bind, app, client, _, _ = demo
    assert login(client).status_code == 200
    registry = app.state.demo_sessions
    old_sid = client.cookies.get(SESSION_COOKIE)
    hashing, release, mutating = Event(), Event(), Event()
    original = service.verify_password
    def slow_password(*args):
        hashing.set()
        assert release.wait(3)
        return original(*args)
    monkeypatch.setattr(service, "verify_password", slow_password)
    def new_login():
        with registry.operation(bind, uid(3)) as db:
            result = registry.prepare_login(db, "demo-employee@example.com", PASSWORD)
        return result.authentication_context_id
    def change():
        mutating.set()
        with registry.operation(bind, uid(3)) as db:
            if mutation == "revoke":
                registry.prepare_revocation(db, uid(3), uid(3), old_sid, reason="Fictional logout all")
            else:
                invalidate_user_sessions(db, uid(3), actor_user_id=uid(1), reason="SECURITY_CHANGE")
    with ThreadPoolExecutor(max_workers=3) as executor:
        first = executor.submit(new_login)
        try:
            assert hashing.wait(3)
            # Another thread can access registry memory while password verification
            # is blocked. No concurrent SQLite transactions on a StaticPool connection.
            assert executor.submit(registry.snapshot, old_sid).result(timeout=1) is not None
            second = executor.submit(change)
            assert mutating.wait(1)
            assert not second.done()
        finally:
            release.set()
        new_sid = first.result(timeout=5)
        second.result(timeout=5)
    with pytest.raises(AuthenticationError), registry.operation(bind, uid(3)) as db:
        registry.validate(db, new_sid)


def test_configuration_adapter_never_initializes_normal_settings(monkeypatch):
    import builtins
    import importlib
    import sys
    from scripts.run_local_demo import install_demo_configuration, demo_engine_options
    original_import = builtins.__import__
    normal_config = sys.modules["app.core.config"]
    normal_database = sys.modules["app.core.database"]
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("AUTH_ALLOWED_ORIGINS", "not-valid-json")
        patch.setenv("DEBUG", "not-a-boolean")
        patch.delitem(sys.modules, "app.core.config")
        patch.delitem(sys.modules, "app.core.database")
        def guard(name, *args, **kwargs):
            if name == "app.core" or name.startswith("app.core."):
                raise AssertionError("Normal configuration/database import attempted")
            return original_import(name, *args, **kwargs)
        patch.setattr(builtins, "__import__", guard)
        settings = install_demo_configuration()
        assert importlib.import_module("app.core.config").settings is settings
        assert settings.DEBUG is False and settings.AUTH_ALLOWED_ORIGINS == []
        assert settings.DATABASE_URL == "sqlite:///:memory:"
        with pytest.raises(ValueError, match="fresh process"):
            install_demo_configuration()
    assert sys.modules["app.core.config"] is normal_config
    assert sys.modules["app.core.database"] is normal_database
    assert demo_engine_options()["pool_timeout"] == 5
    assert demo_engine_options()["connect_args"]["connect_timeout"] == 5


@pytest.mark.parametrize("bad", ["\u00e9", "\u2603", "a" * 2049, "", "bad.token"])
def test_malformed_csrf_is_rejected_not_500(demo, bad):
    from starlette.requests import Request
    from fastapi import HTTPException
    from app.services.demo_transport import DemoTransport
    _, app, _, _, _ = demo
    transport = DemoTransport(app.state.demo_sessions, [ORIGIN])
    # ASGI decodes raw HTTP headers as Latin-1. A non-ASCII codepoint such as
    # snowman is represented here by its UTF-8 bytes, as a raw client might send.
    request = Request({"type": "http", "method": "POST", "scheme": "https", "path": "/auth/login",
        "query_string": b"", "server": ("localhost", 443), "client": ("127.0.0.1", 50000),
        "headers": [(b"host", b"localhost"), (b"origin", ORIGIN.encode()),
                    (b"x-csrf-token", bad.encode("utf-8")),
                    (b"cookie", (CSRF_COOKIE + "=" + bad).encode("utf-8"))]})
    with pytest.raises(HTTPException) as denied:
        transport.verify(request)
    assert denied.value.status_code == 403


def test_registry_retention_is_bounded_without_audit_deletion(demo):
    from dataclasses import replace
    import secrets
    _, app, client, _, _ = demo
    assert login(client).status_code == 200
    registry = app.state.demo_sessions
    original = next(iter(registry.sessions.values()))
    with registry.lock:
        for _ in range(registry.max_retained_per_user + 20):
            registry.publish_login(replace(original, authentication_context_id=secrets.token_urlsafe(32), revoked=True))
    assert len(registry.sessions) <= registry.max_retained_per_user


@pytest.fixture
def high_super_lock_world(monkeypatch):
    """Independent SQLite copies for deterministic row-lock modelling, never PG."""
    from app.services.demo_authentication import DemoSessions
    manifest, target = contracts()
    values = manifest.model_dump(mode="json")
    values["initial_super_admin"] = uid(9)
    values["users"][0]["id"] = uid(9)
    manifest = boot.DemoManifest.model_validate(values)
    engines = []
    try:
        for _ in range(2):
            bind = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
            engines.append(bind)
            Base.metadata.create_all(bind)
            with Session(bind) as db, db.begin():
                boot.bootstrap(db, manifest, target, operator="FICTIONAL-LOCK-TEST",
                               passwords={str(u.id): PASSWORD for u in manifest.users})
        monkeypatch.setattr(boot, "verify_target", lambda db, target: None)
        registry = DemoSessions(manifest, target)
        with registry.operation(engines[0], uid(9)) as db:
            actor = registry.prepare_login(db, "demo-super@example.com", PASSWORD)
        with registry.operation(engines[0], uid(3)) as db:
            employee = registry.prepare_login(db, "demo-employee@example.com", PASSWORD)
        yield engines, registry, actor.authentication_context_id, employee.authentication_context_id
    finally:
        for bind in engines:
            bind.dispose()


def test_cross_service_database_lock_order_with_high_super_id(high_super_lock_world, monkeypatch):
    """Model row contention around real SELECTs, not SQLite row-lock semantics.

    SQL transactions use separate in-memory engines so no overlapping transactions
    share a StaticPool connection. The shared lock model represents the same user
    IDs and checks actual statement order from both real service implementations.
    """
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event, RLock, current_thread
    from app.services import organization_management as organization
    engines, registry, actor_sid, _ = high_super_lock_world
    inventory_engine, organization_engine = engines
    assert uid(9) > uid(3)
    row_locks = {uid(n): RLock() for n in (2, 3, 9)}
    held, traces = {}, {}
    inventory_has_lower, organization_attempted = Event(), Event()
    original_execute, original_validate = Session.execute, registry.validate

    def tracked_execute(db, statement, *args, **kwargs):
        columns = list(getattr(statement, "selected_columns", ()))
        if (getattr(statement, "_for_update_arg", None) is not None and len(columns) == 1
                and getattr(getattr(columns[0], "table", None), "name", None) == "users"
                and columns[0].name == "id"):
            assert list(statement._order_by_clauses) == [User.id.__clause_element__()]
            parameters = statement.compile().params
            selected = next((set(value) for value in parameters.values() if isinstance(value, list)), set(row_locks))
            order = sorted(selected & set(row_locks))
            worker = current_thread().name
            if db.get_bind() is organization_engine:
                organization_attempted.set()
            for user_id in order:
                assert row_locks[user_id].acquire(timeout=3), "Modelled row lock timed out"
                held.setdefault(worker, []).append(user_id)
                traces.setdefault(worker, []).append(user_id)
                if db.get_bind() is inventory_engine and user_id == uid(3):
                    inventory_has_lower.set()
                    assert organization_attempted.wait(3)
        return original_execute(db, statement, *args, **kwargs)

    def validate_after_full_lock_set(db, sid, **kwargs):
        if db.get_bind() is inventory_engine:
            assert held.get(current_thread().name) == [uid(3), uid(9)]
        return original_validate(db, sid, **kwargs)

    def release_model_rows(db, transaction):
        if transaction.parent is None:
            for user_id in reversed(held.pop(current_thread().name, [])):
                row_locks[user_id].release()

    monkeypatch.setattr(Session, "execute", tracked_execute)
    monkeypatch.setattr(registry, "validate", validate_after_full_lock_set)
    event.listen(Session, "after_transaction_end", release_model_rows)
    def inventory():
        with registry.operation(inventory_engine, uid(9), uid(3)) as db:
            registry.validate(db, actor_sid)
            return registry.inventory(db, uid(9), uid(3), actor_sid)
    def mutate():
        assert inventory_has_lower.wait(3)
        with Session(organization_engine) as source:
            with organization.mutation(source, uid(9), organization.A.IDENTITY_ADMINISTER) as db:
                # Exercise the actual mutation context and its audit-atomic service.
                from app.services import identity_service as identity
                previous = identity.read_identity_state(db, uid(3))
                identity.update_organization_profile(db, uid(3), {"name": "Fictional revised employee"},
                    expected_revision=previous.revision,
                    evidence=identity.IdentityEvidence(uid(9), "Fictional lock ordering regression"))
    try:
        with ThreadPoolExecutor(max_workers=2, thread_name_prefix="ordered-lock-test") as executor:
            inventory_result = executor.submit(inventory)
            mutation_result = executor.submit(mutate)
            assert inventory_result.result(timeout=8)["items"][0]["state"] == "ACTIVE"
            mutation_result.result(timeout=8)
        assert sorted(traces.values()) == sorted([[uid(3), uid(9)], [uid(2), uid(3), uid(9)]])
        assert not held
    finally:
        event.remove(Session, "after_transaction_end", release_model_rows)


@pytest.mark.parametrize("change", ["revoke", "identity"])
def test_ordered_cross_user_operations_do_not_resurrect_sessions(high_super_lock_world, change):
    from app.services.authentication_common import AuthenticationError
    from app.services.authentication_sessions import invalidate_user_sessions
    engines, registry, actor_sid, employee_sid = high_super_lock_world
    bind = engines[0]
    with registry.operation(bind, uid(9), uid(3)) as db:
        registry.validate(db, actor_sid)
        assert registry.inventory(db, uid(9), uid(3), actor_sid)["items"][0]["state"] == "ACTIVE"
        if change == "revoke":
            registry.prepare_revocation(db, uid(9), uid(3), actor_sid,
                                        session_ref=fingerprint(employee_sid), reason="Fictional revocation")
        else:
            invalidate_user_sessions(db, uid(3), actor_user_id=uid(9), reason="SECURITY_CHANGE")
    with pytest.raises(AuthenticationError), registry.operation(bind, uid(3)) as db:
        registry.validate(db, employee_sid, touch=True)
    with registry.operation(bind, uid(9), uid(3)) as db:
        registry.validate(db, actor_sid)
        assert registry.inventory(db, uid(9), uid(3), actor_sid)["items"][0]["state"] in {"REVOKED", "INVALIDATED"}
