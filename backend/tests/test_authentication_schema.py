from datetime import timedelta
import secrets

import pytest
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import (User, UserAuthenticationState, MFACredential, AuthenticationChallenge,
                        AuthenticationSession, RecoveryCode, AuthenticationRateLimit)
from app.services.authentication_challenges import ChallengePurpose, create_challenge
from app.services.authentication_recovery import hash_recovery_code, store_recovery_hash
from app.services.mfa_encryption import MFASecretCipher
from tests.test_authentication_infrastructure import engine, NOW, active_credential, issue


def pending_credential(user_id="user", **changes):
    values = dict(user_id=user_id, secret_ciphertext=secrets.token_bytes(60), key_version="test-v1",
                  status="PENDING", enrolled_at=NOW)
    return MFACredential(**{**values, **changes})


def test_encrypted_storage_user_relationship_and_version_persist(engine):
    key, secret, credential_id = secrets.token_bytes(32), b"FICTIONAL-TEST-SECRET", "test-credential"
    cipher = MFASecretCipher({"test-v1": key}, "test-v1")
    encrypted = cipher.encrypt(secret, user_id="user", credential_id=credential_id)
    with Session(engine) as db, db.begin():
        db.add(pending_credential(id=credential_id, secret_ciphertext=encrypted.ciphertext, key_version=encrypted.key_version))
    with Session(engine) as db:
        row = db.get(MFACredential, credential_id)
        assert row.user.id == "user" and row.key_version == "test-v1"
        assert row.secret_ciphertext == encrypted.ciphertext and secret not in row.secret_ciphertext


def test_one_active_and_one_pending_credential_allow_replacement_without_losing_history(engine):
    with Session(engine) as db, db.begin():
        active_credential(db)
        pending = pending_credential()
        db.add(pending)
        db.flush()
        pending_id = pending.id
    with Session(engine) as db:
        with pytest.raises(IntegrityError), db.begin():
            db.add(pending_credential())
            db.flush()
    with Session(engine) as db:
        with pytest.raises(IntegrityError), db.begin():
            db.add(pending_credential(status="ACTIVE", activated_at=NOW))
            db.flush()
    with Session(engine) as db, db.begin():
        row = db.get(MFACredential, pending_id)
        row.status, row.revoked_at, row.revocation_reason = "REVOKED", NOW, "TEST_REPLACEMENT"
        db.flush()
        db.add(pending_credential())
    with Session(engine) as db:
        assert db.query(MFACredential).count() == 3


@pytest.mark.parametrize("changes", [
    {"secret_ciphertext": b"plaintext"}, {"key_version": ""}, {"last_accepted_step": -1},
    {"status": "INVALID"}, {"status": "ACTIVE"}, {"status": "REVOKED"},
    {"activated_at": NOW - timedelta(seconds=1)}, {"revoked_at": NOW - timedelta(seconds=1)},
    {"user_id": "unknown"},
])
def test_mfa_storage_constraints(engine, changes):
    with Session(engine) as db:
        with pytest.raises(IntegrityError), db.begin():
            db.add(pending_credential(**changes))
            db.flush()


@pytest.mark.parametrize("changes", [
    {"purpose": "APPLICATION_ACCESS"}, {"challenge_type": "FULL_SESSION"}, {"security_generation": -1},
    {"expires_at": NOW}, {"attempts": -1}, {"attempts": 6}, {"max_attempts": 0},
    {"consumed_at": NOW, "revoked_at": NOW}, {"token_hash": "raw-token"},
])
def test_challenge_constraints(engine, changes):
    with Session(engine) as db:
        with pytest.raises(IntegrityError), db.begin():
            values = dict(user_id="user", purpose="MFA_VERIFICATION", challenge_type="PASSWORD_VERIFIED",
                security_generation=0, created_at=NOW, expires_at=NOW + timedelta(seconds=300),
                attempts=0, max_attempts=5, token_hash="a" * 64)
            db.add(AuthenticationChallenge(**{**values, **changes}))
            db.flush()


@pytest.mark.parametrize("changes", [
    {"mfa_method": "PASSWORD"}, {"mfa_verified_at": None}, {"security_generation": -1},
    {"expires_at": NOW}, {"idle_expires_at": NOW}, {"last_activity_at": NOW - timedelta(seconds=1)},
    {"revoked_at": NOW}, {"id": "not-opaque"},
])
def test_session_constraints(engine, changes):
    with Session(engine) as db, db.begin():
        principal, ticket, credential_id = issue(db)
        # A distinct valid challenge for the copied session avoids masking other
        # constraints behind the one-session-per-challenge unique constraint.
        another = create_challenge(db, "user", ChallengePurpose.MFA_VERIFICATION, now=NOW)
    with Session(engine) as db:
        with pytest.raises(IntegrityError), db.begin():
            values = dict(id=secrets.token_urlsafe(32), user_id="user", credential_id=credential_id,
                challenge_id=another.challenge_id, security_generation=0, created_at=NOW,
                expires_at=NOW + timedelta(seconds=1800), idle_expires_at=NOW + timedelta(seconds=900),
                last_activity_at=NOW, mfa_verified_at=NOW, mfa_method="TOTP")
            db.add(AuthenticationSession(**{**values, **changes}))
            db.flush()


def test_only_one_session_can_reference_a_verification_challenge(engine):
    with Session(engine) as db, db.begin():
        principal, ticket, credential_id = issue(db)
    with Session(engine) as db:
        with pytest.raises(IntegrityError), db.begin():
            db.add(AuthenticationSession(id=secrets.token_urlsafe(32), user_id="user", credential_id=credential_id,
                challenge_id=ticket.challenge_id, security_generation=0, created_at=NOW,
                expires_at=NOW + timedelta(seconds=1800), idle_expires_at=NOW + timedelta(seconds=900),
                last_activity_at=NOW, mfa_verified_at=NOW, mfa_method="TOTP"))
            db.flush()


def test_recovery_plaintext_and_duplicate_hash_rejected_by_schema(engine):
    with Session(engine) as db:
        with pytest.raises(IntegrityError), db.begin():
            db.add(RecoveryCode(user_id="user", code_hash="plaintext-recovery-code", security_generation=0, created_at=NOW))
            db.flush()
    encoded = hash_recovery_code("FICTIONAL-RECOVERY-CODE-TEST-ONLY")
    with Session(engine) as db, db.begin():
        db.add(RecoveryCode(user_id="user", code_hash=encoded, security_generation=0, created_at=NOW))
    with Session(engine) as db:
        with pytest.raises(IntegrityError), db.begin():
            db.add(RecoveryCode(user_id="user", code_hash=encoded, security_generation=0, created_at=NOW))
            db.flush()


@pytest.mark.parametrize("changes", [{"attempts": 0}, {"attempts": 7}, {"threshold": 0}, {"window_seconds": 0},
                                        {"bucket_key": "account-email"}, {"category": "UNKNOWN"}, {"expires_at": NOW}])
def test_rate_limit_constraints(engine, changes):
    with Session(engine) as db:
        with pytest.raises(IntegrityError), db.begin():
            values = dict(bucket_key="a" * 64, category="PASSWORD_ACCOUNT", attempts=1, threshold=5,
                          window_seconds=300, window_started_at=NOW, expires_at=NOW + timedelta(seconds=300))
            db.add(AuthenticationRateLimit(**{**values, **changes}))
            db.flush()


def test_authentication_history_restricts_user_deletion_and_is_not_populated_for_others(engine):
    with Session(engine) as db, db.begin():
        issue(db)
    with Session(engine) as db:
        with pytest.raises(IntegrityError), db.begin():
            db.execute(delete(User).where(User.id == "user"))
    with Session(engine) as db:
        assert db.get(User, "user") is not None
        assert db.get(UserAuthenticationState, "other") is None
        assert db.query(AuthenticationSession).count() == 1
