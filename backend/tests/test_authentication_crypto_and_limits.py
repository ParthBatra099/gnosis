import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import json
import secrets
from threading import Lock
from types import SimpleNamespace

import pytest
from pydantic import SecretStr
from sqlalchemy import event, select
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.core.config import Settings, settings
from app.models import AuthenticationRateLimit
from app.services.authentication_common import AuthenticationError
from app.services.authentication_rate_limits import (
    RateLimitCategory, RateLimitPolicy, RateLimitUnavailable, bucket_key, record_attempt,
)
from app.services.mfa_encryption import EncryptedSecret, MFAEncryptionError, MFASecretCipher
from tests.test_authentication_infrastructure import engine, NOW


def test_authenticated_encryption_bound_to_credential_and_version(caplog):
    key = secrets.token_bytes(32)
    cipher = MFASecretCipher({"v1": key, "v2": key}, "v1")
    plaintext = b"FICTIONAL-TOTP-SECRET-TEST-ONLY"
    first = cipher.encrypt(plaintext, user_id="user", credential_id="credential")
    second = cipher.encrypt(plaintext, user_id="user", credential_id="credential")
    assert first.ciphertext != second.ciphertext
    assert plaintext not in first.ciphertext
    assert cipher.decrypt(first, user_id="user", credential_id="credential") == plaintext
    for encrypted, user, credential in [
        (EncryptedSecret(first.ciphertext[:-1] + bytes([first.ciphertext[-1] ^ 1]), "v1"), "user", "credential"),
        (EncryptedSecret(first.ciphertext, "v2"), "user", "credential"),
        (EncryptedSecret(first.ciphertext, "unknown"), "user", "credential"),
        (first, "other", "credential"), (first, "user", "other"),
    ]:
        with pytest.raises(MFAEncryptionError):
            cipher.decrypt(encrypted, user_id=user, credential_id=credential)
    assert plaintext.decode() not in caplog.text
    assert plaintext.decode() not in repr(first)


def test_rotation_reads_retained_versions_and_writes_active_version():
    old_key, new_key = secrets.token_bytes(32), secrets.token_bytes(32)
    old = MFASecretCipher({"v1": old_key}, "v1")
    payload = old.encrypt(b"disposable-test-secret", user_id="user", credential_id="credential")
    rotated = MFASecretCipher({"v1": old_key, "v2": new_key}, "v2")
    plaintext = rotated.decrypt(payload, user_id="user", credential_id="credential")
    replacement = rotated.encrypt(plaintext, user_id="user", credential_id="credential")
    assert replacement.key_version == "v2"
    assert rotated.decrypt(replacement, user_id="user", credential_id="credential") == plaintext
    with pytest.raises(MFAEncryptionError):
        MFASecretCipher({"v2": new_key}, "v2").decrypt(payload, user_id="user", credential_id="credential")


@pytest.mark.parametrize("ring,version", [
    (None, None), ("{}", "v1"), ('{"v1":"not-base64"}', "v1"),
    ('{"v1":"' + base64.b64encode(b"short").decode() + '"}', "v1"),
    ('{"v1":"x","v1":"y"}', "v1"), ("[]", "v1"),
])
def test_missing_or_invalid_managed_encryption_configuration_fails_closed(ring, version):
    configuration = Settings(_env_file=None, MFA_ENCRYPTION_KEYS=ring, MFA_ENCRYPTION_ACTIVE_KEY_VERSION=version)
    with pytest.raises(MFAEncryptionError):
        MFASecretCipher.from_settings(configuration)


def test_secret_configuration_is_redacted_and_separate_from_jwt_key():
    encoded = base64.b64encode(secrets.token_bytes(32)).decode()
    configuration = Settings(_env_file=None, MFA_ENCRYPTION_KEYS=json.dumps({"v1": encoded}), MFA_ENCRYPTION_ACTIVE_KEY_VERSION="v1")
    assert encoded not in repr(configuration)
    assert MFASecretCipher.from_settings(configuration).active_version == "v1"
    assert configuration.MFA_ENCRYPTION_KEYS.get_secret_value() != configuration.JWT_SECRET_KEY


def test_rate_limit_atomic_counter_threshold_saturation_and_window(engine):
    key = secrets.token_bytes(32)
    policy = RateLimitPolicy(threshold=3, window_seconds=60)
    results = []
    for index in range(10):
        with Session(engine) as db, db.begin():
            results.append(record_attempt(db, RateLimitCategory.PASSWORD_ACCOUNT, " Person@Example.test ", policy=policy, key=key, now=NOW))
    assert [result.allowed for result in results] == [True] * 3 + [False] * 7
    assert results[-1].attempts == 4 and results[-1].retry_after_seconds == 60
    with Session(engine) as db, db.begin():
        reset = record_attempt(db, RateLimitCategory.PASSWORD_ACCOUNT, "person@example.test", policy=policy, key=key, now=NOW + timedelta(seconds=60))
        assert reset.allowed and reset.attempts == 1
        row = db.scalar(select(AuthenticationRateLimit))
        assert row.category == "PASSWORD_ACCOUNT" and len(row.bucket_key) == 64
        assert "person" not in row.bucket_key


def test_rate_limits_separate_categories_and_normalize_only_safe_identifiers():
    key = secrets.token_bytes(32)
    assert bucket_key("PASSWORD_ACCOUNT", " USER@EXAMPLE.TEST ", key=key) == bucket_key("PASSWORD_ACCOUNT", "user@example.test", key=key)
    assert bucket_key("PASSWORD_ACCOUNT", "user", key=key) != bucket_key("MFA_ACCOUNT", "user", key=key)
    assert bucket_key("MFA_CHALLENGE", "one", key=key) != bucket_key("MFA_CHALLENGE", "two", key=key)
    for invalid in ("", " ", "user\nname", "x" * 513):
        with pytest.raises(AuthenticationError):
            bucket_key("PASSWORD_ACCOUNT", invalid, key=key)


def test_rate_limit_storage_error_and_missing_key_fail_closed(engine, monkeypatch):
    monkeypatch.setattr(settings, "AUTH_RATE_LIMIT_KEY", None)
    with pytest.raises(RateLimitUnavailable):
        bucket_key("PASSWORD_ACCOUNT", "user")
    with Session(engine) as db, db.begin():
        def unavailable(*args, **kwargs):
            raise OperationalError("unavailable", {}, RuntimeError("offline"))
        monkeypatch.setattr(db, "execute", unavailable)
        with pytest.raises(RateLimitUnavailable, match="storage is unavailable"):
            record_attempt(db, "PASSWORD_ACCOUNT", "user", key=secrets.token_bytes(32), now=NOW)


def test_live_rate_policy_mismatch_fails_closed_and_expired_bucket_adopts_policy(engine):
    key = secrets.token_bytes(32)
    with Session(engine) as db, db.begin():
        record_attempt(db, "MFA_CHALLENGE", "challenge", policy=RateLimitPolicy(2, 60), key=key, now=NOW)
    with Session(engine) as db:
        with pytest.raises(RateLimitUnavailable), db.begin():
            record_attempt(db, "MFA_CHALLENGE", "challenge", policy=RateLimitPolicy(3, 60), key=key, now=NOW)
    with Session(engine) as db, db.begin():
        result = record_attempt(db, "MFA_CHALLENGE", "challenge", policy=RateLimitPolicy(3, 60), key=key, now=NOW + timedelta(seconds=60))
        assert result.allowed and result.attempts == 1


def test_cooperating_workers_share_one_persisted_counter(engine):
    # In-memory SQLite is a single shared DBAPI connection. The harness serializes
    # transactions; PostgreSQL's UPSERT provides this serialization in production.
    # This does not claim a real multi-connection PostgreSQL concurrency test.
    lock, key = Lock(), secrets.token_bytes(32)
    def worker(_):
        with lock, Session(engine) as db, db.begin():
            return record_attempt(db, "RECOVERY_ACCOUNT", "user", policy=RateLimitPolicy(4, 60), key=key, now=NOW).allowed
    with ThreadPoolExecutor(max_workers=4) as executor:
        decisions = list(executor.map(worker, range(20)))
    assert sum(decisions) == 4
    with Session(engine) as db:
        assert db.scalar(select(AuthenticationRateLimit.attempts)) == 5


def test_actual_postgresql_upsert_branch_compiles_without_connection(engine, monkeypatch):
    statements = []
    # Construct the actual PostgreSQL code path, but intercept execution before
    # any engine/connect operation. Dialect-specific UPSERT objects cannot be
    # cross-compiled from SQLite to PostgreSQL.
    with Session(engine) as db, db.begin():
        monkeypatch.setattr(db, "get_bind", lambda: SimpleNamespace(dialect=postgresql.dialect()))
        def capture(statement):
            statements.append(str(statement.compile(dialect=postgresql.dialect())))
            return SimpleNamespace(one_or_none=lambda: SimpleNamespace(attempts=1, expires_at=NOW + timedelta(seconds=300)))
        monkeypatch.setattr(db, "execute", capture)
        assert record_attempt(db, "PASSWORD_ACCOUNT", "user", key=secrets.token_bytes(32), now=NOW).allowed
    assert len(statements) == 1
    assert "ON CONFLICT (bucket_key) DO UPDATE" in statements[0]
    assert "CASE WHEN" in statements[0] and "RETURNING" in statements[0]
