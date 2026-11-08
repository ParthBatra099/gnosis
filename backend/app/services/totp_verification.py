"""Interoperable six-digit TOTP verification; Unit 5 owns replay consumption."""
from dataclasses import dataclass, field
import hmac
import re

import pyotp

from app.core.config import settings
from app.models import MFACredential
from app.services.authentication_common import AuthenticationError, clock
from app.services.authentication_sessions import TOTPVerification
from app.services.mfa_encryption import EncryptedSecret, MFASecretCipher


def generator(secret):
    return pyotp.TOTP(secret, digits=6, interval=settings.MFA_TOTP_INTERVAL_SECONDS)


def accepted_step(secret, code, *, now=None, previous_step=None):
    timestamp = clock(now)
    if not isinstance(code, str) or not re.fullmatch(r"[0-9]{6}", code):
        raise AuthenticationError("Authentication failed")
    current = int(timestamp.timestamp()) // settings.MFA_TOTP_INTERVAL_SECONDS
    matches = []
    totp = generator(secret)
    for delta in range(-settings.MFA_TOTP_CLOCK_SKEW_STEPS, settings.MFA_TOTP_CLOCK_SKEW_STEPS + 1):
        step = current + delta
        if step >= 0 and hmac.compare_digest(totp.at(step * settings.MFA_TOTP_INTERVAL_SECONDS), code):
            matches.append(step)
    if not matches or (previous_step is not None and max(matches) <= previous_step):
        raise AuthenticationError("Authentication failed")
    return max(matches)


def plaintext_secret(credential):
    return MFASecretCipher.from_settings().decrypt(
        EncryptedSecret(credential.secret_ciphertext, credential.key_version),
        user_id=credential.user_id, credential_id=credential.id).decode("ascii")


@dataclass(repr=False)
class TOTPVerificationProvider:
    credential_id: str
    code: str = field(repr=False)
    now: object = field(default=None, repr=False)

    def verify_for_session(self, db, *, user_id, challenge):
        credential = db.query(MFACredential).filter_by(id=self.credential_id, user_id=user_id, status="ACTIVE").populate_existing().first()
        if credential is None:
            raise AuthenticationError("Authentication failed")
        timestamp = clock(self.now)
        step = accepted_step(plaintext_secret(credential), self.code, now=timestamp,
                             previous_step=credential.last_accepted_step)
        return TOTPVerification(user_id, challenge.challenge_id, challenge.security_generation,
                                credential.id, timestamp, step)
