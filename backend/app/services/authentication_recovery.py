"""Hash-only recovery inventory and atomic consumption, not a recovery workflow."""
from argon2 import PasswordHasher, Type, extract_parameters
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import update

from app.models import RecoveryCode
from app.services.authentication_common import AuthenticationError, audit, clock, locked_state

_hasher = PasswordHasher(type=Type.ID)


def hash_recovery_code(code):
    # Unit 6 must generate high-entropy, independent codes. Never log this input.
    if not isinstance(code, str) or not 20 <= len(code) <= 256:
        raise AuthenticationError("Invalid recovery-code material")
    return _hasher.hash(code)


def store_recovery_hash(db, user_id, code_hash, *, now=None):
    """Only an encoded strong Argon2id hash is accepted; no plaintext field."""
    try:
        if not isinstance(code_hash, str) or len(code_hash) > 255:
            raise ValueError
        parameters = extract_parameters(code_hash)
        if (parameters.type is not Type.ID or parameters.version != 19 or not 19456 <= parameters.memory_cost <= 262144
                or not 2 <= parameters.time_cost <= 5 or not 1 <= parameters.parallelism <= 8
                or not 16 <= parameters.salt_len <= 64 or not 32 <= parameters.hash_len <= 64):
            raise ValueError
    except (ValueError, TypeError, InvalidHashError):
        raise AuthenticationError("A valid strong Argon2id recovery hash is required") from None
    timestamp = clock(now)
    state = locked_state(db, user_id)
    code = RecoveryCode(user_id=user_id, code_hash=code_hash, security_generation=state.security_generation, created_at=timestamp)
    db.add(code)
    audit(db, user_id=user_id, action="AUTH_RECOVERY_CODE_STORED")
    return code.id


def consume_recovery_code(db, user_id, code_id, candidate, *, now=None):
    """Returns no session/verification proof. Unit 6 must require replacement TOTP.

    Inventory selection and failed-guess throttling belong to the restricted,
    password-verified recovery workflow. No public endpoint is provided here.
    """
    timestamp = clock(now)
    state = locked_state(db, user_id)
    code = db.query(RecoveryCode).filter_by(id=code_id, user_id=user_id).populate_existing().first()
    if (code is None or code.consumed_at is not None or code.security_generation != state.security_generation
            or not isinstance(candidate, str) or not 20 <= len(candidate) <= 256):
        raise AuthenticationError("Recovery code is invalid or unavailable")
    try:
        _hasher.verify(code.code_hash, candidate)
    except (InvalidHashError, VerificationError, VerifyMismatchError):
        raise AuthenticationError("Recovery code is invalid or unavailable") from None
    result = db.execute(update(RecoveryCode).where(RecoveryCode.id == code_id, RecoveryCode.user_id == user_id,
        RecoveryCode.security_generation == state.security_generation, RecoveryCode.consumed_at.is_(None))
        .values(consumed_at=timestamp).returning(RecoveryCode.id).execution_options(synchronize_session=False)).scalar_one_or_none()
    if result is None:
        raise AuthenticationError("Recovery code was already consumed")
    audit(db, user_id=user_id, action="AUTH_RECOVERY_CODE_CONSUMED")
    return True
