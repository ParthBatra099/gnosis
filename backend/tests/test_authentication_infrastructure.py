"""Unit 5 only: all identities, keys, credentials and sessions are disposable."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import secrets

import pytest
from sqlalchemy import create_engine, event, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.models import (Base, Department, User, AuditEvent, UserAuthenticationState, MFACredential,
                        AuthenticationChallenge, AuthenticationSession, RecoveryCode)
from app.services.authentication_challenges import (
    ChallengePolicy, ChallengePurpose, ChallengeTicket, consume_challenge, create_challenge,
    record_challenge_failure, validate_challenge,
)
from app.services.authentication_common import AuthenticationError
from app.services.authentication_recovery import consume_recovery_code, hash_recovery_code, store_recovery_hash
from app.services.authentication_sessions import (
    SessionPolicy, TOTPVerification, create_session, invalidate_user_sessions, revoke_session, validate_session,
)
from app.services.mfa_encryption import MFASecretCipher

NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)


@pytest.fixture
def engine():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    @event.listens_for(engine, "connect")
    def enforce_fk(connection, record):
        connection.execute("PRAGMA foreign_keys=ON")
    # Explicit nullable pre-0010 transition fixture; final-schema tests are separate.
    from tests.identity_transition_support import create_transition_schema
    create_transition_schema(engine)
    with Session(engine) as db, db.begin():
        db.add(Department(id="dept", name="Test department"))
        db.flush()
        for identifier, role, active in [("user", "EMPLOYEE", True), ("other", "EMPLOYEE", True),
                                          ("inactive", "EMPLOYEE", False), ("legacy", None, True)]:
            db.add(User(id=identifier, name=identifier, email=f"{identifier}@example.com", password_hash="unused",
                        role="ADMIN", organization_role=role, department_id="dept", active=active))
    yield engine
    engine.dispose()


class TestOnlyVerifier:
    __test__ = False
    def __init__(self, credential_id, *, step=100, verified_at=NOW):
        self.credential_id, self.step, self.verified_at = credential_id, step, verified_at

    def verify_for_session(self, db, *, user_id, challenge):
        return TOTPVerification(user_id, challenge.challenge_id, challenge.security_generation,
                                self.credential_id, self.verified_at, self.step)


def active_credential(db, user_id="user"):
    credential = db.scalar(select(MFACredential).where(MFACredential.user_id == user_id, MFACredential.status == "ACTIVE"))
    if credential is None:
        credential_id = secrets.token_hex(16)
        cipher = MFASecretCipher({"disposable-v1": secrets.token_bytes(32)}, "disposable-v1")
        encrypted = cipher.encrypt(b"FICTIONAL-TEST-TOTP-SECRET", user_id=user_id, credential_id=credential_id)
        credential = MFACredential(id=credential_id, user_id=user_id, secret_ciphertext=encrypted.ciphertext,
            key_version=encrypted.key_version, status="ACTIVE", enrolled_at=NOW - timedelta(minutes=1), activated_at=NOW)
        db.add(credential)
        db.flush()
    return credential


def issue(db, *, user_id="user", purpose=ChallengePurpose.MFA_VERIFICATION, step=100, now=NOW, policy=None):
    ticket = create_challenge(db, user_id, purpose, now=now)
    credential = active_credential(db, user_id)
    principal = create_session(db, user_id, ticket, verifier=TestOnlyVerifier(credential.id, step=step, verified_at=now),
                               now=now, policy=policy)
    return principal, ticket, credential.id


@pytest.mark.parametrize("purpose", list(ChallengePurpose))
def test_challenge_is_restricted_expiring_and_single_use(engine, purpose):
    with Session(engine) as db, db.begin():
        ticket = create_challenge(db, "user", purpose, now=NOW)
        stored = db.get(AuthenticationChallenge, ticket.challenge_id)
        assert stored.token_hash != ticket.secret and ticket.secret not in repr(ticket)
        assert validate_challenge(db, "user", ticket, purpose, now=NOW).purpose is purpose
        with pytest.raises(AuthenticationError):
            validate_session(db, "user", ticket.secret, now=NOW)
        consume_challenge(db, "user", ticket, purpose, now=NOW)
    with Session(engine) as db, db.begin():
        with pytest.raises(AuthenticationError):
            consume_challenge(db, "user", ticket, purpose, now=NOW)


@pytest.mark.parametrize("failure", ["expired", "wrong_purpose", "wrong_user", "wrong_secret", "revoked", "generation", "future"])
def test_invalid_challenges_fail_closed(engine, failure):
    with Session(engine) as db, db.begin():
        ticket = create_challenge(db, "user", ChallengePurpose.MFA_VERIFICATION, now=NOW)
        if failure == "revoked":
            db.get(AuthenticationChallenge, ticket.challenge_id).revoked_at = NOW
        if failure == "generation":
            db.get(UserAuthenticationState, "user").security_generation += 1
        db.flush()
        with pytest.raises(AuthenticationError):
            validate_challenge(db, "other" if failure == "wrong_user" else "user",
                replace(ticket, secret="x" * 43) if failure == "wrong_secret" else ticket,
                ChallengePurpose.ACCOUNT_RECOVERY if failure == "wrong_purpose" else ChallengePurpose.MFA_VERIFICATION,
                now=NOW + timedelta(seconds=300) if failure == "expired" else NOW - timedelta(seconds=1) if failure == "future" else NOW)


def test_challenge_failure_counter_exhaustion_is_persisted(engine):
    with Session(engine) as db, db.begin():
        ticket = create_challenge(db, "user", ChallengePurpose.MFA_VERIFICATION, policy=ChallengePolicy(300, 2), now=NOW)
        assert record_challenge_failure(db, "user", ticket, ChallengePurpose.MFA_VERIFICATION, now=NOW) == 1
    with Session(engine) as db, db.begin():
        assert record_challenge_failure(db, "user", ticket, ChallengePurpose.MFA_VERIFICATION, now=NOW) == 2
    with Session(engine) as db:
        assert db.get(AuthenticationChallenge, ticket.challenge_id).attempts == 2
        with pytest.raises(AuthenticationError):
            validate_challenge(db, "user", ticket, ChallengePurpose.MFA_VERIFICATION, now=NOW)


@pytest.mark.parametrize("role", ["SUPER_ADMIN", "DEPARTMENT_ADMIN", "EMPLOYEE"])
def test_each_canonical_role_requires_persisted_totp_session(engine, role):
    with Session(engine) as db, db.begin():
        db.get(User, "user").organization_role = role
        db.flush()
        principal, ticket, credential_id = issue(db)
    with Session(engine) as db:
        validated = validate_session(db, "user", principal.authentication_context_id, now=NOW)
        assert validated.subject_user_id == "user"
        assert validated.authentication_context_id == principal.authentication_context_id
        session = db.get(AuthenticationSession, principal.authentication_context_id)
        assert session.mfa_method == "TOTP" and session.credential_id == credential_id
        assert session.expires_at.replace(tzinfo=timezone.utc) == NOW + timedelta(minutes=30)
        assert db.get(AuthenticationChallenge, ticket.challenge_id).consumed_at is not None
        assert db.get(MFACredential, credential_id).last_accepted_step == 100


@pytest.mark.parametrize("verifier", [None, True, {"mfa": True}, {"password_verified": True}])
def test_password_or_claims_cannot_create_session(engine, verifier):
    with Session(engine) as db, db.begin():
        ticket = create_challenge(db, "user", ChallengePurpose.MFA_VERIFICATION, now=NOW)
    with Session(engine) as db:
        with pytest.raises(AuthenticationError), db.begin():
            create_session(db, "user", ticket, verifier=verifier, now=NOW)
    with Session(engine) as db:
        assert db.query(AuthenticationSession).count() == 0
        assert db.get(AuthenticationChallenge, ticket.challenge_id).consumed_at is None


@pytest.mark.parametrize("identity", ["inactive", "legacy", "unknown"])
def test_unavailable_canonical_identity_cannot_get_challenge(engine, identity):
    with Session(engine) as db:
        with pytest.raises(AuthenticationError), db.begin():
            create_challenge(db, identity, ChallengePurpose.MFA_VERIFICATION, now=NOW)


@pytest.mark.parametrize("invalid", ["expired", "idle", "revoked", "inactive", "generation", "missing", "wrong_user", "null_role", "revoked_credential"])
def test_session_validator_uses_current_database_state(engine, invalid):
    with Session(engine) as db, db.begin():
        principal, _, credential_id = issue(db)
        sid = principal.authentication_context_id
        if invalid == "revoked":
            revoke_session(db, sid, actor_user_id="user", now=NOW)
        elif invalid == "inactive":
            db.get(User, "user").active = False
        elif invalid == "null_role":
            db.get(User, "user").organization_role = None
        elif invalid == "generation":
            db.get(UserAuthenticationState, "user").security_generation += 1
        elif invalid == "revoked_credential":
            credential = db.get(MFACredential, credential_id)
            credential.status, credential.revoked_at, credential.revocation_reason = "REVOKED", NOW, "SECURITY_CHANGE"
    with Session(engine) as db:
        with pytest.raises(AuthenticationError):
            validate_session(db, "other" if invalid == "wrong_user" else "user", "x" * 43 if invalid == "missing" else sid,
                             now=NOW + timedelta(seconds=1800 if invalid == "expired" else 900) if invalid in {"expired", "idle"} else NOW)


def test_revocation_is_immediate_even_with_stale_orm_object(engine):
    with Session(engine) as db, db.begin():
        principal, _, _ = issue(db)
    with Session(engine, expire_on_commit=False) as reader:
        stale = reader.get(AuthenticationSession, principal.authentication_context_id)
        reader.commit()
        with Session(engine) as writer, writer.begin():
            assert revoke_session(writer, stale.id, actor_user_id="user", now=NOW)
            assert not revoke_session(writer, stale.id, actor_user_id="user", now=NOW)
        assert stale.revoked_at is None
        with pytest.raises(AuthenticationError):
            validate_session(reader, "user", stale.id, now=NOW)


def test_idle_touch_never_extends_absolute_expiry(engine):
    with Session(engine) as db, db.begin():
        principal, _, _ = issue(db)
    for seconds in (600, 1200, 1799):
        with Session(engine) as db, db.begin():
            validate_session(db, "user", principal.authentication_context_id, touch=True, now=NOW + timedelta(seconds=seconds))
            session = db.get(AuthenticationSession, principal.authentication_context_id)
            assert session.idle_expires_at <= session.expires_at
    with Session(engine) as db:
        with pytest.raises(AuthenticationError):
            validate_session(db, "user", principal.authentication_context_id, now=NOW + timedelta(seconds=1800))


def test_security_generation_invalidates_all_sessions_challenges_and_recovery(engine):
    candidate = "FICTIONAL-RECOVERY-CODE-ONLY-FOR-TEST"
    with Session(engine) as db, db.begin():
        first, _, _ = issue(db)
        second, _, _ = issue(db, step=101)
        ticket = create_challenge(db, "user", ChallengePurpose.ACCOUNT_RECOVERY, now=NOW)
        code_id = store_recovery_hash(db, "user", hash_recovery_code(candidate), now=NOW)
        assert invalidate_user_sessions(db, "user", actor_user_id="user", now=NOW) == 1
    with Session(engine) as db, db.begin():
        for principal in (first, second):
            with pytest.raises(AuthenticationError):
                validate_session(db, "user", principal.authentication_context_id, now=NOW)
        with pytest.raises(AuthenticationError):
            validate_challenge(db, "user", ticket, ChallengePurpose.ACCOUNT_RECOVERY, now=NOW)
        with pytest.raises(AuthenticationError):
            consume_recovery_code(db, "user", code_id, candidate, now=NOW)
        # Existing active TOTP can verify afresh under the new security generation.
        fresh, _, _ = issue(db, step=102)
        assert fresh.security_generation == 1


def test_totp_replay_and_challenge_reuse_cannot_issue_twice(engine):
    with Session(engine) as db, db.begin():
        first, ticket, credential_id = issue(db)
        other_ticket = create_challenge(db, "user", ChallengePurpose.MFA_VERIFICATION, now=NOW)
    for target in (ticket, other_ticket):
        with Session(engine) as db:
            with pytest.raises(AuthenticationError), db.begin():
                create_session(db, "user", target, verifier=TestOnlyVerifier(credential_id), now=NOW)
    with Session(engine) as db:
        assert db.query(AuthenticationSession).count() == 1
        assert db.get(AuthenticationChallenge, other_ticket.challenge_id).consumed_at is None


def test_recovery_challenge_is_never_full_session_proof(engine):
    with Session(engine) as db, db.begin():
        ticket = create_challenge(db, "user", ChallengePurpose.ACCOUNT_RECOVERY, now=NOW)
        credential_id = active_credential(db).id
    with Session(engine) as db:
        with pytest.raises(AuthenticationError), db.begin():
            create_session(db, "user", ticket, verifier=TestOnlyVerifier(credential_id), now=NOW)


def test_recovery_hash_only_atomic_single_use(engine, caplog):
    candidate = "FICTIONAL-SINGLE-USE-RECOVERY-CODE"
    with Session(engine) as db, db.begin():
        create_challenge(db, "user", ChallengePurpose.ACCOUNT_RECOVERY, now=NOW)
        code_id = store_recovery_hash(db, "user", hash_recovery_code(candidate), now=NOW)
        code = db.get(RecoveryCode, code_id)
        assert code.code_hash.startswith("$argon2id$") and candidate not in code.code_hash
        assert consume_recovery_code(db, "user", code_id, candidate, now=NOW) is True
    with Session(engine) as db:
        with pytest.raises(AuthenticationError), db.begin():
            consume_recovery_code(db, "user", code_id, candidate, now=NOW)
        assert db.query(AuthenticationSession).count() == 0
    assert candidate not in caplog.text


@pytest.mark.parametrize("value", ["plain-recovery-code", "sha256:abc", "$argon2id$invalid"])
def test_plaintext_or_invalid_recovery_storage_rejected(engine, value):
    with Session(engine) as db:
        with pytest.raises(AuthenticationError), db.begin():
            store_recovery_hash(db, "user", value, now=NOW)


def test_authentication_audit_failure_rolls_back_session_challenge_and_step(engine):
    with Session(engine) as db, db.begin():
        ticket = create_challenge(db, "user", ChallengePurpose.MFA_VERIFICATION, now=NOW)
        credential_id = active_credential(db).id
    def fail(mapper, connection, audit):
        if audit.action == "AUTH_SESSION_CREATED":
            raise RuntimeError("strict auth audit failure")
    event.listen(AuditEvent, "before_insert", fail)
    try:
        with Session(engine) as db:
            with pytest.raises(RuntimeError, match="strict auth audit failure"), db.begin():
                create_session(db, "user", ticket, verifier=TestOnlyVerifier(credential_id), now=NOW)
    finally:
        event.remove(AuditEvent, "before_insert", fail)
    with Session(engine) as db:
        assert db.query(AuthenticationSession).count() == 0
        assert db.get(AuthenticationChallenge, ticket.challenge_id).consumed_at is None
        assert db.get(MFACredential, credential_id).last_accepted_step is None
        assert db.query(AuditEvent).filter_by(action="AUTH_CHALLENGE_CONSUMED").count() == 0


def test_no_authentication_mutation_implicitly_commits(engine):
    with Session(engine) as db:
        with pytest.raises(RuntimeError), db.begin():
            issue(db)
            raise RuntimeError("caller rollback")
    with Session(engine) as db:
        for model in (UserAuthenticationState, MFACredential, AuthenticationChallenge, AuthenticationSession, AuditEvent):
            assert db.query(model).count() == 0
        with pytest.raises(AuthenticationError, match="explicit caller-owned"):
            create_challenge(db, "user", ChallengePurpose.MFA_VERIFICATION, now=NOW)


@pytest.mark.parametrize("invalid", ["wrong_user", "wrong_challenge", "wrong_generation", "stale", "future", "password_result", "negative_step"])
def test_verifier_result_must_be_fresh_bound_totp_evidence(engine, invalid):
    with Session(engine) as db, db.begin():
        ticket = create_challenge(db, "user", ChallengePurpose.MFA_VERIFICATION, now=NOW)
        credential_id = active_credential(db).id
    class InvalidProvider:
        def verify_for_session(self, db, *, user_id, challenge):
            proof = TOTPVerification(user_id, challenge.challenge_id, challenge.security_generation, credential_id, NOW, 100)
            if invalid == "wrong_user": return replace(proof, user_id="other")
            if invalid == "wrong_challenge": return replace(proof, challenge_id="other")
            if invalid == "wrong_generation": return replace(proof, security_generation=1)
            if invalid == "stale": return replace(proof, verified_at=NOW - timedelta(seconds=61))
            if invalid == "future": return replace(proof, verified_at=NOW + timedelta(seconds=1))
            if invalid == "password_result": return {"password_verified": True, "mfa": True}
            return replace(proof, accepted_step=-1)
    with Session(engine) as db:
        with pytest.raises(AuthenticationError), db.begin():
            create_session(db, "user", ticket, verifier=InvalidProvider(), now=NOW)
    with Session(engine) as db:
        assert db.query(AuthenticationSession).count() == 0
        assert db.get(AuthenticationChallenge, ticket.challenge_id).consumed_at is None


def test_challenge_conditional_consume_rejects_interleaved_consumption(engine, monkeypatch):
    from app.services import authentication_challenges as service
    with Session(engine) as db, db.begin():
        ticket = create_challenge(db, "user", ChallengePurpose.MFA_VERIFICATION, now=NOW)
    original = service.validate_challenge
    def interleave(db, *args, **kwargs):
        view = original(db, *args, **kwargs)
        # Deterministic database change between validation and conditional UPDATE.
        # Real multi-connection PostgreSQL concurrency remains a deployment check.
        db.execute(update(AuthenticationChallenge).where(AuthenticationChallenge.id == ticket.challenge_id).values(consumed_at=NOW))
        return view
    monkeypatch.setattr(service, "validate_challenge", interleave)
    with Session(engine) as db:
        with pytest.raises(AuthenticationError, match="already used or invalidated"), db.begin():
            consume_challenge(db, "user", ticket, ChallengePurpose.MFA_VERIFICATION, now=NOW)


@pytest.mark.parametrize("action", ["AUTH_CHALLENGE_CREATED", "AUTH_CHALLENGE_CONSUMED", "AUTH_CHALLENGE_FAILED",
                                    "AUTH_SESSION_REVOKED", "AUTH_GENERATION_CHANGED", "AUTH_RECOVERY_CODE_CONSUMED"])
def test_authentication_state_and_audit_are_one_transaction(engine, action):
    candidate = "FICTIONAL-RECOVERY-ATOMICITY-TEST"
    with Session(engine) as db, db.begin():
        principal, _, _ = issue(db)
        ticket = create_challenge(db, "user", ChallengePurpose.ACCOUNT_RECOVERY, now=NOW)
        code_id = store_recovery_hash(db, "user", hash_recovery_code(candidate), now=NOW)
    def fail(mapper, connection, audit):
        if audit.action == action:
            raise RuntimeError("atomic authentication audit")
    event.listen(AuditEvent, "before_insert", fail)
    try:
        with Session(engine) as db:
            with pytest.raises(RuntimeError, match="atomic authentication audit"), db.begin():
                if action == "AUTH_CHALLENGE_CREATED":
                    create_challenge(db, "user", ChallengePurpose.MFA_VERIFICATION, now=NOW)
                elif action == "AUTH_CHALLENGE_CONSUMED":
                    consume_challenge(db, "user", ticket, ChallengePurpose.ACCOUNT_RECOVERY, now=NOW)
                elif action == "AUTH_CHALLENGE_FAILED":
                    record_challenge_failure(db, "user", ticket, ChallengePurpose.ACCOUNT_RECOVERY, now=NOW)
                elif action == "AUTH_SESSION_REVOKED":
                    revoke_session(db, principal.authentication_context_id, actor_user_id="user", now=NOW)
                elif action == "AUTH_GENERATION_CHANGED":
                    invalidate_user_sessions(db, "user", actor_user_id="user", now=NOW)
                else:
                    consume_recovery_code(db, "user", code_id, candidate, now=NOW)
    finally:
        event.remove(AuditEvent, "before_insert", fail)
    with Session(engine) as db:
        assert db.query(AuthenticationChallenge).count() == 2
        assert db.get(AuthenticationChallenge, ticket.challenge_id).consumed_at is None
        assert db.get(AuthenticationChallenge, ticket.challenge_id).attempts == 0
        assert db.get(AuthenticationSession, principal.authentication_context_id).revoked_at is None
        assert db.get(UserAuthenticationState, "user").security_generation == 0
        assert db.get(RecoveryCode, code_id).consumed_at is None


def test_session_validation_rejects_broken_persisted_verification_chain(engine):
    with Session(engine) as db, db.begin():
        principal, ticket, _ = issue(db)
        db.get(AuthenticationChallenge, ticket.challenge_id).consumed_at = None
    with Session(engine) as db:
        with pytest.raises(AuthenticationError, match="verification challenge"):
            validate_session(db, "user", principal.authentication_context_id, now=NOW)


@pytest.mark.parametrize("purpose", [ChallengePurpose.MFA_ENROLLMENT, ChallengePurpose.REPLACEMENT_ENROLLMENT])
def test_enrollment_session_requires_new_credential_not_preexisting_totp(engine, purpose):
    with Session(engine) as db, db.begin():
        ticket = create_challenge(db, "user", purpose, now=NOW)
        old_id = active_credential(db).id
    with Session(engine) as db:
        with pytest.raises(AuthenticationError, match="new MFA credential"), db.begin():
            create_session(db, "user", ticket, verifier=TestOnlyVerifier(old_id), now=NOW)
    with Session(engine) as db, db.begin():
        old = db.get(MFACredential, old_id)
        old.status, old.revoked_at, old.revocation_reason = "REVOKED", NOW, "MFA_REPLACED"
        db.flush()
        new = active_credential(db)
        # Simulate Unit 6's newly verified/activated replacement, not a real workflow.
        new.enrolled_at = NOW
        db.flush()
        principal = create_session(db, "user", ticket, verifier=TestOnlyVerifier(new.id), now=NOW)
    with Session(engine) as db:
        assert validate_session(db, "user", principal.authentication_context_id, now=NOW).subject_user_id == "user"


def test_security_state_and_challenges_not_created_by_existing_login(engine):
    from fastapi.testclient import TestClient
    from app.core.database import get_db
    from app.core.security import hash_password
    from app.main import app
    with Session(engine) as db, db.begin():
        db.get(User, "user").password_hash = hash_password("Fictional-Password-Only-Test")
    def override_db():
        with Session(engine) as db:
            yield db
    app.dependency_overrides[get_db] = override_db
    try:
        with TestClient(app, base_url="https://testserver", client=("127.0.0.1", 50000)) as client:
            from tests.authentication_support import browser_post
            response = browser_post(client, "/auth/login", {"email": "user@example.com", "password": "Fictional-Password-Only-Test"})
            assert response.status_code == 200
            # Unit 6 supersedes Unit 5 login compatibility: restricted challenge only.
            assert "access_token" not in response.json()
            assert client.get("/auth/me").status_code == 401
    finally:
        app.dependency_overrides.clear()
    with Session(engine) as db:
        assert db.query(UserAuthenticationState).count() == 1
        assert db.query(AuthenticationChallenge).count() == 1
        assert db.query(AuthenticationSession).count() == 0
