import base64
from datetime import datetime, timedelta, timezone
import json
import secrets
from urllib.parse import urlparse, parse_qs

from fastapi.testclient import TestClient
import pyotp
import pytest
from pydantic import SecretStr
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.core.database import Base, get_db
from app.core.security import create_access_token, hash_password
from app.main import create_app
from app.models import (Department, User, MFACredential, AuthenticationChallenge, AuthenticationSession,
                        UserAuthenticationState, RecoveryCode, AuditEvent)
from app.services import mfa_workflows as workflows
from app.services import authentication_rate_limits as limits
from app.services.authentication_common import utc
from app.services.authentication_transport import SESSION_COOKIE, CSRF_COOKIE

ORIGIN = "https://testserver"
PASSWORD = "Fictional-Password-For-Isolated-MFA-Test"
NOW = datetime.now(timezone.utc).replace(microsecond=0)


class TestOnlyAuthorizer:
    __test__ = False
    def authorize_enrollment(self, db, *, user_id, challenge):
        return workflows.EnrollmentAuthorization(user_id, challenge.challenge_id, challenge.security_generation,
            "FICTIONAL-INDEPENDENT-APPROVAL", "FICTIONAL-INDEPENDENT-OPERATOR", challenge.expires_at)


@pytest.fixture
def world(monkeypatch):
    encoded = lambda: base64.b64encode(secrets.token_bytes(32)).decode()
    monkeypatch.setattr(settings, "MFA_ENCRYPTION_KEYS", SecretStr(json.dumps({"test-v1": encoded()})))
    monkeypatch.setattr(settings, "MFA_ENCRYPTION_ACTIVE_KEY_VERSION", "test-v1")
    monkeypatch.setattr(settings, "AUTH_RATE_LIMIT_KEY", SecretStr(encoded()))
    monkeypatch.setattr(settings, "AUTH_CSRF_KEY", SecretStr(encoded()))
    monkeypatch.setattr(settings, "AUTH_ALLOWED_ORIGINS", [ORIGIN])
    monkeypatch.setattr(settings, "AUTH_TRUSTED_PROXY_CIDRS", [])
    monkeypatch.setattr(settings, "AUTH_ALLOW_BEARER_SESSIONS", False)
    monkeypatch.setattr(settings, "AUTH_RATE_LIMIT_THRESHOLD", 100)
    monkeypatch.setattr(settings, "AUTH_SOURCE_RATE_LIMIT_THRESHOLD", 1000)
    monkeypatch.setattr(settings, "MFA_RECOVERY_CODE_COUNT", 2)
    monkeypatch.setattr(workflows, "clock", lambda *args: NOW)
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    @event.listens_for(engine, "connect")
    def foreign_keys(connection, record):
        connection.execute("PRAGMA foreign_keys=ON")
    # Explicit nullable pre-0010 transition fixture; final-schema tests are separate.
    from tests.identity_transition_support import create_transition_schema
    create_transition_schema(engine)
    with Session(engine) as db, db.begin():
        db.add(Department(id="dept", name="Test department")); db.flush()
        for identifier, role in [("super", "SUPER_ADMIN"), ("admin", "DEPARTMENT_ADMIN"), ("employee", "EMPLOYEE")]:
            db.add(User(id=identifier, name=identifier, email=f"{identifier}@example.com", password_hash=hash_password(PASSWORD),
                        role="ADMIN", organization_role=role, department_id="dept", active=True))
    app = create_app()
    def database():
        with Session(engine, autoflush=False) as db:
            yield db
    app.dependency_overrides[get_db] = database
    with TestClient(app, base_url=ORIGIN, client=("127.0.0.1", 50000)) as client:
        yield engine, client, app
    engine.dispose()


def post(client, path, payload):
    csrf = client.get("/auth/csrf", headers={"Origin": ORIGIN})
    assert csrf.status_code == 200, csrf.text
    return client.post(path, json=payload, headers={"Origin": ORIGIN, "X-CSRF-Token": csrf.json()["csrf_token"]})


def password(client, actor="employee", recover=False):
    return post(client, "/auth/login", {"email": actor + "@example.com", "password": PASSWORD, "intent": "recover" if recover else "login"})


def ticket(response):
    data = response.json()
    return {key: data[key] for key in ("challenge_id", "challenge_secret")}


def enroll(world, actor="employee"):
    engine, client, app = world
    app.state.enrollment_authorizer = TestOnlyAuthorizer()
    challenge = password(client, actor)
    assert challenge.status_code == 200, challenge.text
    capability = ticket(challenge)
    started = post(client, "/auth/mfa/enroll", capability)
    assert started.status_code == 200, started.text
    secret = parse_qs(urlparse(started.json()["provisioning_uri"]).query)["secret"][0]
    response = post(client, "/auth/mfa/enroll/verify", {**capability, "code": pyotp.TOTP(secret).at(NOW)})
    assert response.status_code == 200, response.text
    return secret, response.json()["recovery_codes"], capability


@pytest.mark.parametrize("actor", ["super", "admin", "employee"])
def test_all_roles_require_authorized_enrollment_and_totp(world, actor):
    engine, client, app = world
    response = password(client, actor)
    assert response.status_code == 200 and response.json()["next_step"] == "MFA_ENROLLMENT"
    assert "access_token" not in response.json() and SESSION_COOKIE not in client.cookies
    assert client.get("/auth/me").status_code == 401
    assert post(client, "/auth/mfa/enroll", ticket(response)).status_code == 401
    with Session(engine) as db:
        assert db.query(MFACredential).count() == db.query(AuthenticationSession).count() == 0
    secret, codes, _ = enroll(world, actor)
    assert len(codes) == 2 and all(len(code) >= 20 for code in codes)
    assert client.get("/auth/me").status_code == 200
    with Session(engine) as db:
        assert db.query(MFACredential).filter_by(status="ACTIVE").count() == 1
        assert db.query(AuthenticationSession).count() == 1
        credential = db.scalar(select(MFACredential))
        assert secret.encode() not in credential.secret_ciphertext
        assert credential.key_version == "test-v1" and credential.last_accepted_step is not None
        assert all(code not in row.code_hash for row in db.scalars(select(RecoveryCode)) for code in codes)


def test_generation_alone_does_not_activate_and_invalid_codes_commit_failures(world):
    engine, client, app = world
    app.state.enrollment_authorizer = TestOnlyAuthorizer()
    challenge = ticket(password(client))
    response = post(client, "/auth/mfa/enroll", challenge)
    assert response.status_code == 200
    assert post(client, "/auth/mfa/enroll/verify", {**challenge, "code": "not-an-otp"}).status_code == 401
    with Session(engine) as db:
        assert db.scalar(select(MFACredential.status)) == "PENDING"
        assert db.get(AuthenticationChallenge, challenge["challenge_id"]).attempts == 1
        assert db.query(AuthenticationSession).count() == 0


def test_login_replay_wrong_purpose_and_old_tokens_are_rejected(world, monkeypatch):
    engine, client, app = world
    secret, codes, old_ticket = enroll(world)
    client.cookies.clear()
    challenge = ticket(password(client))
    assert post(client, "/auth/mfa/verify", {**challenge, "code": pyotp.TOTP(secret).at(NOW)}).status_code == 401
    later = NOW + timedelta(seconds=30)
    monkeypatch.setattr(workflows, "clock", lambda *args: later)
    response = post(client, "/auth/mfa/verify", {**challenge, "code": pyotp.TOTP(secret).at(later)})
    assert response.status_code == 200, response.text
    client.cookies.clear()
    assert post(client, "/auth/mfa/verify", {**challenge, "code": pyotp.TOTP(secret).at(later)}).status_code == 401
    assert post(client, "/auth/mfa/verify", {**old_ticket, "code": pyotp.TOTP(secret).at(later)}).status_code == 401
    legacy = create_access_token("employee")
    assert client.get("/auth/me", headers={"Authorization": "Bearer " + legacy}).status_code == 401
    client.cookies.set(SESSION_COOKIE, legacy)
    assert client.get("/auth/me").status_code == 401


@pytest.mark.parametrize("actor", ["super", "employee"])
def test_recovery_requires_new_totp_replaces_credential_and_invalidates_sessions(world, actor):
    engine, client, app = world
    old_secret, codes, _ = enroll(world, actor)
    old_cookie = client.cookies.get(SESSION_COOKIE)
    recovery = ticket(password(client, actor, recover=True))
    recovered = post(client, "/auth/recovery/verify", {**recovery, "code": codes[0]})
    assert recovered.status_code == 200, recovered.text
    assert recovered.json()["next_step"] == "REPLACEMENT_ENROLLMENT"
    assert "authenticated" not in recovered.json()
    assert client.get("/auth/me").status_code == 401
    replacement = ticket(recovered)
    # Recovery receipt, not an external password-only enrollment grant, authorizes replacement.
    app.state.enrollment_authorizer = None
    started = post(client, "/auth/mfa/enroll", replacement)
    assert started.status_code == 200, started.text
    new_secret = parse_qs(urlparse(started.json()["provisioning_uri"]).query)["secret"][0]
    assert new_secret != old_secret
    assert post(client, "/auth/mfa/enroll/verify", {**replacement, "code": "not-an-otp"}).status_code == 401
    completed = post(client, "/auth/mfa/enroll/verify", {**replacement, "code": pyotp.TOTP(new_secret).at(NOW)})
    assert completed.status_code == 200, completed.text
    assert completed.json()["recovery_codes"] != codes
    assert client.get("/auth/me").status_code == 200
    with Session(engine) as db:
        assert db.get(UserAuthenticationState, actor).security_generation == 2
        assert db.query(MFACredential).filter_by(user_id=actor, status="REVOKED").count() == 1
        assert db.query(MFACredential).filter_by(user_id=actor, status="ACTIVE").count() == 1
        assert db.query(RecoveryCode).filter(RecoveryCode.consumed_at.is_not(None)).count() == 1
    client.cookies.clear(); client.cookies.set(SESSION_COOKIE, old_cookie)
    assert client.get("/auth/me").status_code == 401


def test_cookie_csrf_origin_and_cors_boundary(world):
    engine, client, app = world
    secret, _, _ = enroll(world)
    cookie = client.cookies.get(SESSION_COOKIE)
    assert cookie and "access_token" not in password(client).json()
    assert client.post("/auth/logout").status_code == 403
    csrf = client.get("/auth/csrf", headers={"Origin": ORIGIN})
    assert "Secure" in csrf.headers["set-cookie"] and "HttpOnly" in csrf.headers["set-cookie"]
    assert "SameSite=strict" in csrf.headers["set-cookie"]
    assert client.post("/auth/logout", headers={"Origin": "https://evil.example", "X-CSRF-Token": csrf.json()["csrf_token"]}).status_code == 403
    assert client.options("/auth/login", headers={"Origin": ORIGIN, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "X-CSRF-Token"}).headers["access-control-allow-origin"] == ORIGIN
    denied = client.options("/auth/login", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in denied.headers
    response = client.post("/auth/logout", headers={"Origin": ORIGIN, "X-CSRF-Token": csrf.json()["csrf_token"]})
    assert response.status_code == 204
    client.cookies.set(SESSION_COOKIE, cookie)
    assert client.get("/auth/me").status_code == 401


def test_rate_limits_and_storage_failure_fail_closed(world, monkeypatch):
    engine, client, app = world
    monkeypatch.setattr(settings, "AUTH_RATE_LIMIT_THRESHOLD", 2)
    for _ in range(2):
        assert post(client, "/auth/login", {"email": "employee@example.com", "password": "wrong"}).status_code == 401
    assert password(client).status_code == 429
    def offline(*args, **kwargs):
        raise limits.RateLimitUnavailable("offline")
    monkeypatch.setattr(workflows, "record_attempt", offline)
    assert password(client).status_code == 503
    with Session(engine) as db:
        assert db.query(AuthenticationSession).count() == 0


def test_password_errors_are_neutral_and_secrets_not_audited(world, caplog):
    engine, client, app = world
    unknown = post(client, "/auth/login", {"email": "unknown@example.com", "password": "wrong"})
    known = post(client, "/auth/login", {"email": "employee@example.com", "password": "wrong"})
    assert (unknown.status_code, unknown.json()) == (known.status_code, known.json())
    secret, codes, challenge = enroll(world)
    with Session(engine) as db:
        evidence = json.dumps([row.context_data for row in db.scalars(select(AuditEvent))])
    for value in [secret, PASSWORD, challenge["challenge_secret"], *codes]:
        assert value not in caplog.text and value not in evidence


def test_audit_failure_rolls_back_activation_and_no_cookie_is_issued(world):
    engine, client, app = world
    app.state.enrollment_authorizer = TestOnlyAuthorizer()
    capability = ticket(password(client))
    started = post(client, "/auth/mfa/enroll", capability)
    secret = parse_qs(urlparse(started.json()["provisioning_uri"]).query)["secret"][0]
    def fail(mapper, connection, audit):
        if audit.action == "AUTH_ENROLLMENT_COMPLETED":
            raise RuntimeError("simulated audit failure")
    event.listen(AuditEvent, "before_insert", fail)
    try:
        response = post(client, "/auth/mfa/enroll/verify", {**capability, "code": pyotp.TOTP(secret).at(NOW)})
    finally:
        event.remove(AuditEvent, "before_insert", fail)
    assert response.status_code == 503 and SESSION_COOKIE not in client.cookies
    with Session(engine) as db:
        assert db.scalar(select(MFACredential.status)) == "PENDING"
        assert db.query(AuthenticationSession).count() == 0
        assert db.get(AuthenticationChallenge, capability["challenge_id"]).consumed_at is None


@pytest.mark.parametrize("defect", ["wrong_user", "wrong_challenge", "wrong_generation", "expired", "self_approved", "boolean"])
def test_independent_enrollment_authorization_is_bound_and_not_client_claims(world, defect):
    from dataclasses import replace
    engine, client, app = world
    challenge = ticket(password(client, "super"))
    class BadAuthorizer(TestOnlyAuthorizer):
        def authorize_enrollment(self, db, **kwargs):
            proof = super().authorize_enrollment(db, **kwargs)
            if defect == "boolean": return True
            changes = {"wrong_user": {"user_id": "employee"}, "wrong_challenge": {"challenge_id": "wrong"},
                       "wrong_generation": {"security_generation": 99}, "expired": {"expires_at": NOW},
                       "self_approved": {"verified_by": "super"}}
            return replace(proof, **changes[defect])
    app.state.enrollment_authorizer = BadAuthorizer()
    assert post(client, "/auth/mfa/enroll", challenge).status_code == 401
    with Session(engine) as db:
        assert db.query(MFACredential).count() == db.query(AuthenticationSession).count() == 0


def test_competing_enrollment_challenges_and_repeated_confirmation_cannot_activate_twice(world):
    engine, client, app = world
    app.state.enrollment_authorizer = TestOnlyAuthorizer()
    first, competing = ticket(password(client)), ticket(password(client))
    started = post(client, "/auth/mfa/enroll", first)
    assert started.status_code == 200
    assert post(client, "/auth/mfa/enroll", competing).status_code == 401
    assert post(client, "/auth/mfa/enroll", first).status_code == 401
    secret = parse_qs(urlparse(started.json()["provisioning_uri"]).query)["secret"][0]
    payload = {**first, "code": pyotp.TOTP(secret).at(NOW)}
    assert post(client, "/auth/mfa/enroll/verify", payload).status_code == 200
    assert post(client, "/auth/mfa/enroll/verify", payload).status_code == 401
    with Session(engine) as db:
        assert db.query(MFACredential).filter_by(status="ACTIVE").count() == 1
        assert db.query(AuthenticationSession).count() == 1


@pytest.mark.parametrize("seconds,accepted", [(-60, False), (-30, True), (0, True), (30, True), (60, False)])
def test_totp_skew_is_small_configured_and_six_digits(seconds, accepted):
    from app.services.totp_verification import accepted_step
    from app.services.authentication_common import AuthenticationError
    secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    code = pyotp.TOTP(secret).at(NOW + timedelta(seconds=seconds))
    if accepted:
        assert accepted_step(secret, code, now=NOW) == int((NOW + timedelta(seconds=seconds)).timestamp()) // 30
    else:
        with pytest.raises(AuthenticationError): accepted_step(secret, code, now=NOW)


@pytest.mark.parametrize("issue", ["expired", "wrong_secret", "wrong_purpose"])
def test_enrollment_capability_expiry_and_scope(world, monkeypatch, issue):
    engine, client, app = world
    app.state.enrollment_authorizer = TestOnlyAuthorizer()
    capability = ticket(password(client))
    if issue == "expired": monkeypatch.setattr(workflows, "clock", lambda *args: NOW + timedelta(seconds=301))
    elif issue == "wrong_secret": capability["challenge_secret"] = "x" * 43
    else:
        assert post(client, "/auth/mfa/verify", {**capability, "code": "000000"}).status_code == 401
        return
    assert post(client, "/auth/mfa/enroll", capability).status_code == 401


@pytest.mark.parametrize("state", ["revoked", "generation", "inactive", "unmapped", "absolute_expiry", "idle_expiry"])
def test_http_session_checks_persisted_state(world, monkeypatch, state):
    from app.api import deps
    engine, client, app = world
    enroll(world)
    with Session(engine) as db, db.begin():
        if state == "revoked":
            session = db.scalar(select(AuthenticationSession))
            session.revoked_at, session.revocation_reason = NOW, "SECURITY_CHANGE"
        elif state == "generation": db.get(UserAuthenticationState, "employee").security_generation += 1
        elif state == "inactive": db.get(User, "employee").active = False
        elif state == "unmapped": db.get(User, "employee").organization_role = None
    if state.endswith("expiry"):
        monkeypatch.setattr(deps, "clock", lambda: NOW + timedelta(seconds=1800 if state == "absolute_expiry" else 901))
    assert client.get("/auth/me").status_code == 401


def test_mfa_claim_without_persisted_session_cannot_authenticate(world):
    import jwt
    engine, client, app = world
    for sid in (None, secrets.token_urlsafe(32)):
        payload = {"sub": "super", "mfa": True, "exp": int((NOW + timedelta(hours=1)).timestamp())}
        if sid: payload["sid"] = sid
        client.cookies.set(SESSION_COOKIE, jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM))
        assert client.get("/auth/me").status_code == 401


def test_recovery_audit_failure_rolls_back_consumption_and_invalidation(world):
    engine, client, app = world
    _, codes, _ = enroll(world)
    capability = ticket(password(client, recover=True))
    def fail(mapper, connection, row):
        if row.action == "AUTH_GENERATION_CHANGED": raise RuntimeError("audit unavailable")
    event.listen(AuditEvent, "before_insert", fail)
    try:
        response = post(client, "/auth/recovery/verify", {**capability, "code": codes[0]})
    finally:
        event.remove(AuditEvent, "before_insert", fail)
    assert response.status_code == 503
    assert client.get("/auth/me").status_code == 200
    with Session(engine) as db:
        assert db.get(UserAuthenticationState, "employee").security_generation == 0
        assert db.query(RecoveryCode).filter(RecoveryCode.consumed_at.is_not(None)).count() == 0
        assert db.get(AuthenticationChallenge, capability["challenge_id"]).consumed_at is None


def test_recovery_consumption_and_old_totp_cannot_be_reused_after_replacement(world, monkeypatch):
    engine, client, app = world
    old_secret, codes, _ = enroll(world)
    capability = ticket(password(client, recover=True))
    response = post(client, "/auth/recovery/verify", {**capability, "code": codes[0]})
    assert response.status_code == 200
    assert post(client, "/auth/recovery/verify", {**capability, "code": codes[0]}).status_code == 401
    replacement = ticket(response)
    started = post(client, "/auth/mfa/enroll", replacement)
    new_secret = parse_qs(urlparse(started.json()["provisioning_uri"]).query)["secret"][0]
    assert post(client, "/auth/mfa/enroll/verify", {**replacement, "code": pyotp.TOTP(new_secret).at(NOW)}).status_code == 200
    later = NOW + timedelta(seconds=30)
    monkeypatch.setattr(workflows, "clock", lambda *args: later)
    login_challenge = ticket(password(client))
    assert post(client, "/auth/mfa/verify", {**login_challenge, "code": pyotp.TOTP(old_secret).at(later)}).status_code == 401
    recover_challenge = ticket(password(client, recover=True))
    assert post(client, "/auth/recovery/verify", {**recover_challenge, "code": codes[1]}).status_code == 401


def test_proxy_headers_only_influence_explicitly_trusted_peers(world, monkeypatch):
    from starlette.requests import Request
    from app.services.authentication_transport import source_identifier, secure_request
    def request(peer, headers):
        return Request({"type": "http", "scheme": "http", "path": "/", "server": ("testserver", 80),
                        "client": (peer, 50000), "headers": [(key.encode(), value.encode()) for key, value in headers.items()]})
    spoofed = request("192.0.2.5", {"x-forwarded-for": "198.51.100.9", "x-forwarded-proto": "https"})
    assert source_identifier(spoofed) == "192.0.2.5" and not secure_request(spoofed)
    monkeypatch.setattr(settings, "AUTH_TRUSTED_PROXY_CIDRS", ["192.0.2.0/24"])
    assert source_identifier(spoofed) == "198.51.100.9" and secure_request(spoofed)
    from fastapi import HTTPException
    with pytest.raises(HTTPException): source_identifier(request("192.0.2.5", {"x-forwarded-for": "not-an-ip"}))


def test_csrf_tampering_and_bearer_default_denial(world):
    engine, client, app = world
    enroll(world)
    token = client.cookies.get(SESSION_COOKIE)
    csrf = client.get("/auth/csrf", headers={"Origin": ORIGIN}).json()["csrf_token"]
    assert client.post("/auth/logout", headers={"Origin": ORIGIN, "X-CSRF-Token": csrf + "x"}).status_code == 403
    client.cookies.clear()
    assert client.get("/auth/me", headers={"Authorization": "Bearer " + token}).status_code == 401


def test_missing_keys_fail_closed_without_generating_fallback_material(world, monkeypatch):
    engine, client, app = world
    app.state.enrollment_authorizer = TestOnlyAuthorizer()
    capability = ticket(password(client))
    monkeypatch.setattr(settings, "MFA_ENCRYPTION_KEYS", None)
    assert post(client, "/auth/mfa/enroll", capability).status_code == 503
    with Session(engine) as db: assert db.query(MFACredential).count() == 0
    monkeypatch.setattr(settings, "AUTH_CSRF_KEY", None)
    assert client.get("/auth/csrf", headers={"Origin": ORIGIN}).status_code == 503


def test_mfa_does_not_grant_organizational_or_business_data_authority(world):
    from app.models import Resource
    engine, client, app = world
    with Session(engine) as db, db.begin():
        db.add(Resource(id="critical", name="Sensitive", department_id="dept", owner_id="admin", sensitivity="CRITICAL"))
    enroll(world, "super")
    assert client.get("/resources/critical").status_code == 403
    client.cookies.clear()
    enroll(world, "employee")
    assert client.get("/monitoring/audit-logs").json() == []


def test_insecure_transport_default_signing_key_and_missing_origins_fail_closed(world, monkeypatch):
    engine, client, app = world
    with TestClient(app, base_url="http://testserver", client=("127.0.0.1", 50000)) as insecure:
        assert insecure.get("/auth/csrf", headers={"Origin": ORIGIN}).status_code == 403
    monkeypatch.setattr(settings, "JWT_SECRET_KEY", "CHANGEME_SUPER_SECRET_GNOSIS_KEY_32_BYTES_MIN")
    assert password(client).status_code == 503
    monkeypatch.setattr(settings, "AUTH_ALLOWED_ORIGINS", [])
    assert client.get("/auth/csrf", headers={"Origin": ORIGIN}).status_code == 403


def test_session_cookie_attributes_and_csrf_session_binding(world):
    engine, client, app = world
    app.state.enrollment_authorizer = TestOnlyAuthorizer()
    capability = ticket(password(client))
    initial_csrf = client.get("/auth/csrf", headers={"Origin": ORIGIN}).json()["csrf_token"]
    started = post(client, "/auth/mfa/enroll", capability)
    secret = parse_qs(urlparse(started.json()["provisioning_uri"]).query)["secret"][0]
    response = post(client, "/auth/mfa/enroll/verify", {**capability, "code": pyotp.TOTP(secret).at(NOW)})
    cookies = response.headers.get_list("set-cookie")
    assert any(cookie.startswith(SESSION_COOKIE + "=") and "Secure" in cookie and "HttpOnly" in cookie
               and "SameSite=strict" in cookie and "Path=/" in cookie and "Domain=" not in cookie for cookie in cookies)
    assert response.headers["cache-control"] == "no-store"
    # Even replacing both double-submit values with a correctly signed old
    # anonymous token cannot bypass the new session binding.
    client.cookies.set(CSRF_COOKIE, initial_csrf, domain="testserver.local", path="/")
    assert client.post("/auth/logout", headers={"Origin": ORIGIN, "X-CSRF-Token": initial_csrf}).status_code == 403


def test_logout_all_revokes_other_sessions_and_advances_generation(world, monkeypatch):
    engine, client, app = world
    secret, _, _ = enroll(world)
    first_cookie = client.cookies.get(SESSION_COOKIE)
    monkeypatch.setattr(workflows, "clock", lambda *args: NOW + timedelta(seconds=30))
    capability = ticket(password(client))
    assert post(client, "/auth/mfa/verify", {**capability, "code": pyotp.TOTP(secret).at(NOW + timedelta(seconds=30))}).status_code == 200
    # Use a later validation clock too, because this test advances logical time.
    from app.api import deps
    monkeypatch.setattr(deps, "clock", lambda: NOW + timedelta(seconds=30))
    from app.api.v1 import auth
    monkeypatch.setattr(auth, "clock", lambda: NOW + timedelta(seconds=30))
    assert post(client, "/auth/logout-all", {}).status_code == 204
    client.cookies.set(SESSION_COOKIE, first_cookie)
    assert client.get("/auth/me").status_code == 401
    with Session(engine) as db:
        assert db.get(UserAuthenticationState, "employee").security_generation == 1
        assert db.query(AuthenticationSession).filter_by(revoked_at=None).count() == 0


def test_cooperating_enrollment_workers_obtain_only_one_session(world):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Lock
    engine, client, app = world
    app.state.enrollment_authorizer = TestOnlyAuthorizer()
    capability = ticket(password(client))
    started = post(client, "/auth/mfa/enroll", capability)
    secret = parse_qs(urlparse(started.json()["provisioning_uri"]).query)["secret"][0]
    lock = Lock()
    def worker(_):
        # In-memory SQLite has one DBAPI connection. Serialize the harness only;
        # PostgreSQL user-row locks provide cross-worker serialization in deployment.
        with lock, TestClient(app, base_url=ORIGIN, client=("127.0.0.1", 50000)) as concurrent_client:
            return post(concurrent_client, "/auth/mfa/enroll/verify", {**capability, "code": pyotp.TOTP(secret).at(NOW)}).status_code
    with ThreadPoolExecutor(max_workers=2) as executor:
        assert sorted(executor.map(worker, range(2))) == [200, 401]
    with Session(engine) as db:
        assert db.query(AuthenticationSession).count() == 1
        assert db.query(MFACredential).filter_by(status="ACTIVE").count() == 1


@pytest.mark.parametrize("operation", ["login", "recovery"])
def test_cooperating_verification_workers_cannot_consume_twice(world, monkeypatch, operation):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Lock
    engine, client, app = world
    secret, codes, _ = enroll(world)
    later = NOW + timedelta(seconds=30)
    monkeypatch.setattr(workflows, "clock", lambda *args: later)
    capability = ticket(password(client, recover=operation == "recovery"))
    path = "/auth/recovery/verify" if operation == "recovery" else "/auth/mfa/verify"
    code = codes[0] if operation == "recovery" else pyotp.TOTP(secret).at(later)
    lock = Lock()
    def worker(_):
        # SQLite harness serialization models cooperating transactions, not a
        # real multi-connection PostgreSQL test; production uses the shared lock/CAS.
        with lock, TestClient(app, base_url=ORIGIN, client=("127.0.0.1", 50000)) as worker_client:
            return post(worker_client, path, {**capability, "code": code}).status_code
    with ThreadPoolExecutor(max_workers=2) as executor:
        assert sorted(executor.map(worker, range(2))) == [200, 401]
    with Session(engine) as db:
        assert db.get(AuthenticationChallenge, capability["challenge_id"]).consumed_at is not None
        assert db.query(AuthenticationSession).count() == (1 if operation == "recovery" else 2)
        assert db.query(RecoveryCode).filter(RecoveryCode.consumed_at.is_not(None)).count() == (1 if operation == "recovery" else 0)


def test_replacement_audit_failure_keeps_prior_credential_and_pending_replacement(world):
    engine, client, app = world
    _, codes, _ = enroll(world)
    recovery = ticket(password(client, recover=True))
    response = post(client, "/auth/recovery/verify", {**recovery, "code": codes[0]})
    replacement = ticket(response)
    started = post(client, "/auth/mfa/enroll", replacement)
    secret = parse_qs(urlparse(started.json()["provisioning_uri"]).query)["secret"][0]
    def fail(mapper, connection, row):
        if row.action == "AUTH_MFA_REPLACED": raise RuntimeError("replacement audit unavailable")
    event.listen(AuditEvent, "before_insert", fail)
    try:
        response = post(client, "/auth/mfa/enroll/verify", {**replacement, "code": pyotp.TOTP(secret).at(NOW)})
    finally:
        event.remove(AuditEvent, "before_insert", fail)
    assert response.status_code == 503
    with Session(engine) as db:
        assert db.get(UserAuthenticationState, "employee").security_generation == 1
        assert db.query(MFACredential).filter_by(status="ACTIVE").count() == 1
        assert db.query(MFACredential).filter_by(status="PENDING").count() == 1
        assert db.query(MFACredential).filter_by(status="REVOKED").count() == 0
        assert db.query(AuthenticationSession).count() == 1
        assert db.get(AuthenticationChallenge, replacement["challenge_id"]).consumed_at is None
