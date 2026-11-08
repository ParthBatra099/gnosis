"""Explicit persisted-MFA fixtures for unrelated API regressions, never production.

These represent already enrolled test identities. Workflow tests use real HTTP
TOTP enrollment/verification instead. No authentication dependency is overridden.
"""
import base64
from datetime import datetime, timedelta, timezone
import json
import secrets
import uuid

import pyotp
from pydantic import SecretStr
from sqlalchemy import select, cast, String

from app.core.config import settings
from app.core.security import create_access_token
from app.models import User, UserAuthenticationState, MFACredential, AuthenticationChallenge, AuthenticationSession
from app.services.authentication_common import fingerprint
from app.services.mfa_encryption import MFASecretCipher
from scripts.run_phase1_tests import require_memory_url

ORIGIN = "https://testserver"
TEST_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"


def configure(monkeypatch):
    encoded = lambda: base64.b64encode(secrets.token_bytes(32)).decode()
    monkeypatch.setattr(settings, "MFA_ENCRYPTION_KEYS", SecretStr(json.dumps({"fixture-v1": encoded()})))
    monkeypatch.setattr(settings, "MFA_ENCRYPTION_ACTIVE_KEY_VERSION", "fixture-v1")
    monkeypatch.setattr(settings, "AUTH_RATE_LIMIT_KEY", SecretStr(encoded()))
    monkeypatch.setattr(settings, "AUTH_CSRF_KEY", SecretStr(encoded()))
    monkeypatch.setattr(settings, "AUTH_ALLOWED_ORIGINS", [ORIGIN])
    monkeypatch.setattr(settings, "AUTH_ALLOW_BEARER_SESSIONS", True)
    monkeypatch.setattr(settings, "AUTH_SOURCE_RATE_LIMIT_THRESHOLD", 1000)


def session_token(db, subject, expires_delta=None):
    require_memory_url(db.get_bind().url)
    role = db.scalar(select(cast(User.organization_role, String)).where(User.id == subject))
    if role not in {"SUPER_ADMIN", "DEPARTMENT_ADMIN", "EMPLOYEE"}:
        return create_access_token(subject, expires_delta)  # Deliberate negative fixture; cannot authenticate.
    now = datetime.now(timezone.utc)
    state = db.get(UserAuthenticationState, subject)
    if state is None:
        state = UserAuthenticationState(user_id=subject, created_at=now, updated_at=now)
        db.add(state); db.flush()
    credential = db.query(MFACredential).filter_by(user_id=subject, status="ACTIVE").first()
    if credential is None:
        identifier = str(uuid.uuid4())
        encrypted = MFASecretCipher.from_settings().encrypt(TEST_SECRET.encode(), user_id=subject, credential_id=identifier)
        credential = MFACredential(id=identifier, user_id=subject, secret_ciphertext=encrypted.ciphertext,
            key_version=encrypted.key_version, status="ACTIVE", enrolled_at=now, activated_at=now,
            last_accepted_step=int(now.timestamp()) // 30 - 1)
        db.add(credential); db.flush()
    challenge = AuthenticationChallenge(user_id=subject, token_hash=fingerprint(secrets.token_urlsafe(32)),
        challenge_type="PASSWORD_VERIFIED", purpose="MFA_VERIFICATION", security_generation=state.security_generation,
        created_at=now, expires_at=now + timedelta(minutes=5), consumed_at=now, attempts=0, max_attempts=5)
    db.add(challenge); db.flush()
    sid = secrets.token_urlsafe(32)
    db.add(AuthenticationSession(id=sid, user_id=subject, credential_id=credential.id, challenge_id=challenge.id,
        security_generation=state.security_generation, created_at=now, expires_at=now + timedelta(minutes=30),
        last_activity_at=now, idle_expires_at=now + timedelta(minutes=15), mfa_verified_at=now, mfa_method="TOTP"))
    db.commit()
    return create_access_token(subject, expires_delta, session_id=sid)


def browser_post(client, path, payload):
    response = client.get("/auth/csrf", headers={"Origin": ORIGIN})
    assert response.status_code == 200, response.text
    return client.post(path, json=payload, headers={"Origin": ORIGIN, "X-CSRF-Token": response.json()["csrf_token"]})


def login_mfa(client, db, *, email, password):
    user = db.query(User).filter_by(email=email).one()
    session_token(db, user.id)  # Declare pre-enrolled disposable fixture, not authorization inference.
    response = browser_post(client, "/auth/login", {"email": email, "password": password})
    assert response.status_code == 200, response.text
    data = response.json()
    assert "access_token" not in data and data["next_step"] == "MFA_VERIFICATION"
    verified = browser_post(client, "/auth/mfa/verify", {"challenge_id": data["challenge_id"],
        "challenge_secret": data["challenge_secret"], "code": pyotp.TOTP(TEST_SECRET).now()})
    assert verified.status_code == 200, verified.text
    token = client.cookies.get("__Host-gnosis_session")
    client.cookies.clear()  # Multi-actor API tests use explicit, persisted sid bearer fixtures.
    return token
