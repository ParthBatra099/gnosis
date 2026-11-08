"""Unit 8A profile contract; use the actual persisted-MFA authentication boundary."""
from datetime import timedelta
import secrets

import pytest
from sqlalchemy.orm import Session

from app.api import deps
from app.core.security import create_access_token, decode_access_token
from app.models import AuthenticationSession, User
from app.schemas.user import UserRead
from app.services.authentication_common import utc
from app.services.authentication_transport import SESSION_COOKIE
from tests.authentication_support import session_token
from tests.test_mfa_workflows import world


@pytest.mark.parametrize("actor,canonical", [
    ("super", "SUPER_ADMIN"), ("admin", "DEPARTMENT_ADMIN"), ("employee", "EMPLOYEE"),
])
def test_auth_me_exposes_persisted_canonical_identity_with_legacy_provenance(world, actor, canonical):
    engine, client, _ = world
    with Session(engine) as db:
        token = session_token(db, actor)
        stored = db.get(User, actor)
        expected = {
            "id": stored.id, "name": stored.name, "email": stored.email,
            "role": stored.role, "organization_role": stored.organization_role.value,
            "department_id": stored.department_id, "active": stored.active,
        }
    client.cookies.set(SESSION_COOKIE, token)
    response = client.get("/auth/me")
    assert response.status_code == 200
    assert response.json() == expected  # Exact allowlist excludes all credential/security internals.
    assert response.json()["organization_role"] == canonical
    assert response.json()["role"] == "ADMIN"  # Deliberately different from canonical values.
    assert token not in response.text


@pytest.mark.parametrize("legacy", ["ADMIN", "MANAGER", "EMPLOYEE", "SUPER_ADMIN"])
def test_nullable_persisted_canonical_role_serializes_as_null_without_legacy_inference(world, legacy):
    engine, client, _ = world
    with Session(engine) as db, db.begin():
        db.add(User(id="unmapped", name="Unmapped fixture", email="unmapped@example.com",
                    password_hash="fixture-not-a-usable-password", role=legacy,
                    organization_role=None, department_id="dept", active=True))
    with Session(engine) as db:
        stored = db.get(User, "unmapped")
        profile = UserRead.model_validate(stored).model_dump(mode="json")
        assert profile["organization_role"] is None and profile["role"] == legacy
    # Nullable schema support does not relax the existing session prerequisite.
    client.cookies.set(SESSION_COOKIE, create_access_token("unmapped"))
    assert client.get("/auth/me").status_code == 401


def test_auth_me_without_authentication_reveals_no_profile(world):
    _, client, _ = world
    response = client.get("/auth/me")
    assert response.status_code == 401
    assert "organization_role" not in response.json() and "email" not in response.json()


@pytest.mark.parametrize("failure", ["invalid_token", "unknown_session", "expired_token", "revoked_session", "expired_session", "idle_expired_session"])
def test_auth_me_invalid_expired_or_revoked_sessions_remain_rejected(world, monkeypatch, failure):
    engine, client, _ = world
    with Session(engine) as db:
        token = session_token(db, "employee", timedelta(seconds=-1) if failure == "expired_token" else None)
        if failure != "expired_token":
            sid = decode_access_token(token)["sid"]
            session = db.get(AuthenticationSession, sid)
            if failure == "revoked_session":
                session.revoked_at, session.revocation_reason = session.created_at, "USER_REQUEST"
                db.commit()
            elif failure in {"expired_session", "idle_expired_session"}:
                expiry = utc(session.expires_at if failure == "expired_session" else session.idle_expires_at)
                monkeypatch.setattr(deps, "clock", lambda: expiry + timedelta(seconds=1))
        if failure == "invalid_token":
            token = "invalid-token"
        elif failure == "unknown_session":
            token = create_access_token("employee", session_id=secrets.token_urlsafe(32))
    client.cookies.set(SESSION_COOKIE, token)
    response = client.get("/auth/me")
    assert response.status_code == 401
    assert "organization_role" not in response.json() and "email" not in response.json()
