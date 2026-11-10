from typing import Literal
from pydantic import BaseModel, EmailStr, Field, SecretStr, ConfigDict, field_validator
from datetime import datetime


class LoginRequest(BaseModel):
    email: EmailStr
    password: SecretStr = Field(min_length=1, max_length=1024)
    intent: Literal["login", "recover"] = "login"


class ChallengeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    challenge_id: str = Field(min_length=1, max_length=36)
    challenge_secret: SecretStr = Field(min_length=43, max_length=128)


class VerificationRequest(ChallengeRequest):
    code: SecretStr = Field(min_length=1, max_length=256)


class SessionRead(BaseModel):
    session_ref: str
    created_at: datetime
    last_activity_at: datetime
    expires_at: datetime
    state: Literal["ACTIVE", "EXPIRED", "REVOKED", "INVALIDATED"]
    is_current: bool


class SessionPage(BaseModel):
    items: list[SessionRead]
    total: int
    limit: int
    offset: int


class SessionRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=1, max_length=2000)

    @field_validator("reason")
    @classmethod
    def meaningful_reason(cls, value):
        if not value.strip():
            raise ValueError("Reason is required")
        return value.strip()
