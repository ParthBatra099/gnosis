from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Sequence
from app.models.access_grant import AccessGrant
from app.models.resource import Resource
from app.models.user import User


class DecisionStatus(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class DecisionReason(str, Enum):
    ALLOW_SAME_DEPARTMENT = "ALLOW_SAME_DEPARTMENT"
    ALLOW_RESOURCE_OWNER = "ALLOW_RESOURCE_OWNER"
    ALLOW_EXPLICIT_GRANT = "ALLOW_EXPLICIT_GRANT"
    DENY_INACTIVE_USER = "DENY_INACTIVE_USER"
    DENY_DEPARTMENT_MISMATCH = "DENY_DEPARTMENT_MISMATCH"
    DENY_UNSUPPORTED_PERMISSION = "DENY_UNSUPPORTED_PERMISSION"
    DENY_SENSITIVITY_EXCEEDED = "DENY_SENSITIVITY_EXCEEDED"


SUPPORTED_PERMISSIONS = {"read", "write", "delete"}


@dataclass(frozen=True)
class AuthorizationDecision:
    status: DecisionStatus
    reason: DecisionReason
    allowed: bool


def evaluate_access(
    user: User,
    resource: Resource,
    requested_permission: str,
    active_grants: Sequence[AccessGrant] | None = None,
) -> AuthorizationDecision:
    """
    Deterministic authorization decision engine.
    Evaluates active/valid grants alongside user attributes, ownership, department, and sensitivity boundaries.
    """
    # Guard Rule 1: Inactive users are always denied
    if not user.active:
        return AuthorizationDecision(
            status=DecisionStatus.DENY,
            reason=DecisionReason.DENY_INACTIVE_USER,
            allowed=False,
        )

    # Guard Rule 2: Requested permission must be explicitly supported
    if requested_permission not in SUPPORTED_PERMISSIONS:
        return AuthorizationDecision(
            status=DecisionStatus.DENY,
            reason=DecisionReason.DENY_UNSUPPORTED_PERMISSION,
            allowed=False,
        )

    # Override Rule 3: Resource owner access
    if resource.owner_id == user.id:
        return AuthorizationDecision(
            status=DecisionStatus.ALLOW,
            reason=DecisionReason.ALLOW_RESOURCE_OWNER,
            allowed=True,
        )

    # Override Rule 4: Valid active explicit grant check
    if active_grants:
        now = datetime.now(timezone.utc)
        has_valid_grant = False

        for g in active_grants:
            if (
                g.user_id == user.id
                and g.resource_id == resource.id
                and g.permission == requested_permission
                and g.revoked_at is None
            ):
                # Ensure timezone-aware comparison for expires_at
                if g.expires_at is None:
                    has_valid_grant = True
                    break
                else:
                    g_expires = g.expires_at
                    if g_expires.tzinfo is None:
                        g_expires = g_expires.replace(tzinfo=timezone.utc)
                    if g_expires > now:
                        has_valid_grant = True
                        break

        if has_valid_grant:
            return AuthorizationDecision(
                status=DecisionStatus.ALLOW,
                reason=DecisionReason.ALLOW_EXPLICIT_GRANT,
                allowed=True,
            )

    # Boundary Rule 5: Basic Department Boundary
    if user.department_id != resource.department_id:
        return AuthorizationDecision(
            status=DecisionStatus.DENY,
            reason=DecisionReason.DENY_DEPARTMENT_MISMATCH,
            allowed=False,
        )

    # Boundary Rule 6: CRITICAL sensitivity boundary (non-owner/non-granted)
    if resource.sensitivity == "CRITICAL" and resource.owner_id != user.id:
        return AuthorizationDecision(
            status=DecisionStatus.DENY,
            reason=DecisionReason.DENY_SENSITIVITY_EXCEEDED,
            allowed=False,
        )

    # Default Rule 7: Matching department access
    return AuthorizationDecision(
        status=DecisionStatus.ALLOW,
        reason=DecisionReason.ALLOW_SAME_DEPARTMENT,
        allowed=True,
    )