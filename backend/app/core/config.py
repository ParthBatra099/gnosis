from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from urllib.parse import urlsplit
import ipaddress


class Settings(BaseSettings):
    PROJECT_NAME: str = "GNOSIS"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    DATABASE_URL: str = "postgresql+psycopg://postgres:root@localhost:5432/gnosis_db"

    # JWT Authentication Settings
    JWT_SECRET_KEY: str = "CHANGEME_SUPER_SECRET_GNOSIS_KEY_32_BYTES_MIN"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # Unit 5 primitives only; these settings do not change existing JWT login.
    AUTH_SESSION_ABSOLUTE_SECONDS: int = Field(default=1800, gt=0)
    AUTH_SESSION_IDLE_SECONDS: int = Field(default=900, gt=0)
    AUTH_CHALLENGE_LIFETIME_SECONDS: int = Field(default=300, gt=0)
    AUTH_CHALLENGE_MAX_ATTEMPTS: int = Field(default=5, gt=0)
    AUTH_VERIFICATION_MAX_AGE_SECONDS: int = Field(default=60, gt=0)
    AUTH_RATE_LIMIT_WINDOW_SECONDS: int = Field(default=300, gt=0)
    AUTH_RATE_LIMIT_THRESHOLD: int = Field(default=5, gt=0)
    MFA_ENCRYPTION_KEYS: SecretStr | None = None  # JSON {key_version: base64_32_byte_key}
    MFA_ENCRYPTION_ACTIVE_KEY_VERSION: str | None = None
    AUTH_RATE_LIMIT_KEY: SecretStr | None = None  # Separate base64 32-byte HMAC key
    AUTH_CSRF_KEY: SecretStr | None = None
    AUTH_ALLOWED_ORIGINS: list[str] = Field(default_factory=list)
    AUTH_TRUSTED_PROXY_CIDRS: list[str] = Field(default_factory=list)
    AUTH_ALLOW_BEARER_SESSIONS: bool = False  # Explicit non-browser clients only
    AUTH_CSRF_LIFETIME_SECONDS: int = Field(default=600, ge=60, le=3600)
    AUTH_SOURCE_RATE_LIMIT_THRESHOLD: int = Field(default=60, ge=1, le=1000000)
    MFA_TOTP_ISSUER: str = Field(default="GNOSIS", min_length=1, max_length=64)
    MFA_TOTP_INTERVAL_SECONDS: int = Field(default=30, ge=15, le=120)
    MFA_TOTP_CLOCK_SKEW_STEPS: int = Field(default=1, ge=0, le=1)
    MFA_RECOVERY_CODE_COUNT: int = Field(default=10, ge=2, le=16)

    @field_validator("AUTH_ALLOWED_ORIGINS")
    @classmethod
    def exact_https_origins(cls, values):
        for value in values:
            origin = urlsplit(value)
            if (origin.scheme != "https" or not origin.hostname or origin.username or origin.password
                    or origin.path or origin.query or origin.fragment or "*" in value
                    or value != f"{origin.scheme}://{origin.netloc}"):
                raise ValueError("Authentication origins must be exact HTTPS origins")
            origin.port  # Reject malformed deployment ports too.
        return list(dict.fromkeys(values))

    @field_validator("AUTH_TRUSTED_PROXY_CIDRS")
    @classmethod
    def explicit_proxy_networks(cls, values):
        for value in values:
            network = ipaddress.ip_network(value, strict=True)
            if network.prefixlen == 0:
                raise ValueError("Trusting every proxy source is prohibited")
        return values

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def assemble_db_connection(cls, v: str) -> str:
        if isinstance(v, str) and v.startswith("postgresql://"):
            return v.replace("postgresql://", "postgresql+psycopg://", 1)
        return v

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()
