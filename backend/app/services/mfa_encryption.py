"""Versioned AES-256-GCM for TOTP material; no fallback keys or provisioning flow."""
import base64
from dataclasses import dataclass, field
import json
import os
import re

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import settings


class MFAEncryptionError(ValueError):
    pass


@dataclass(frozen=True)
class EncryptedSecret:
    ciphertext: bytes = field(repr=False)
    key_version: str


def _version(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", value):
        raise MFAEncryptionError("Invalid encryption key version")
    return value


def decode_managed_key(value):
    try:
        key = base64.b64decode(value, validate=True)
        if len(key) != 32:
            raise ValueError
        return key
    except (ValueError, TypeError):
        raise MFAEncryptionError("A separately managed base64 32-byte key is required") from None


class MFASecretCipher:
    def __init__(self, keys: dict[str, bytes], active_version: str):
        self.active_version = _version(active_version)
        if not keys or any(not isinstance(key, bytes) or len(key) != 32 for key in keys.values()):
            raise MFAEncryptionError("Invalid encryption key ring")
        self._keys = {_version(version): AESGCM(key) for version, key in keys.items()}
        if self.active_version not in self._keys:
            raise MFAEncryptionError("Active encryption key version is unavailable")

    @classmethod
    def from_settings(cls, configuration=settings):
        def unique_pairs(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError
                result[key] = value
            return result
        try:
            if not configuration.MFA_ENCRYPTION_KEYS:
                raise ValueError
            values = json.loads(configuration.MFA_ENCRYPTION_KEYS.get_secret_value(), object_pairs_hook=unique_pairs)
            if not isinstance(values, dict):
                raise ValueError
            return cls({version: decode_managed_key(value) for version, value in values.items()},
                       configuration.MFA_ENCRYPTION_ACTIVE_KEY_VERSION)
        except (ValueError, TypeError, AttributeError):
            raise MFAEncryptionError("MFA encryption configuration is missing or invalid") from None

    @staticmethod
    def _aad(user_id, credential_id, key_version):
        if any(not isinstance(value, str) or not value or len(value) > 36 for value in (user_id, credential_id)):
            raise MFAEncryptionError("Encryption must be bound to user and credential identifiers")
        return json.dumps(["gnosis:totp:v1", user_id, credential_id, key_version], separators=(",", ":")).encode()

    def encrypt(self, secret: bytes, *, user_id: str, credential_id: str):
        if not isinstance(secret, bytes) or not 1 <= len(secret) <= 1024:
            raise MFAEncryptionError("Invalid secret material")
        nonce = os.urandom(12)
        ciphertext = self._keys[self.active_version].encrypt(
            nonce, secret, self._aad(user_id, credential_id, self.active_version))
        return EncryptedSecret(nonce + ciphertext, self.active_version)

    def decrypt(self, encrypted: EncryptedSecret, *, user_id: str, credential_id: str):
        try:
            version = _version(encrypted.key_version)
            if version not in self._keys or not isinstance(encrypted.ciphertext, bytes) or len(encrypted.ciphertext) <= 28:
                raise ValueError
            return self._keys[version].decrypt(encrypted.ciphertext[:12], encrypted.ciphertext[12:],
                                             self._aad(user_id, credential_id, version))
        except (ValueError, TypeError, AttributeError, InvalidTag):
            raise MFAEncryptionError("Encrypted MFA material could not be authenticated") from None
