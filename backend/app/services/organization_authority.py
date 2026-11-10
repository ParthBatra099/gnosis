"""Organizational policy only; an ALLOW is not authentication or business-data access.

Consumers remain unchanged until Unit 4. Future authentication must supply the actor
from a trusted principal, and Units 5/6 must validate the server-tracked MFA session.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Protocol

from sqlalchemy import String, cast, select
from sqlalchemy.orm import Session, SessionTransactionOrigin

from app.core.constants import OrganizationRole
from app.models import AccessRequest, Department, DepartmentAdminAssignment, Resource, User
from app.services.identity_service import lock_identity


class AdministrativeAction(str, Enum):
    ORGANIZATION_ADMINISTER = "ORGANIZATION_ADMINISTER"
    IDENTITY_ADMINISTER = "IDENTITY_ADMINISTER"
    DEPARTMENT_ASSIGNMENTS_ADMINISTER = "DEPARTMENT_ASSIGNMENTS_ADMINISTER"
    ORGANIZATION_SECURITY_MONITOR = "ORGANIZATION_SECURITY_MONITOR"
    DEPARTMENT_ADMINISTER = "DEPARTMENT_ADMINISTER"
    ACCESS_REQUEST_APPROVE = "ACCESS_REQUEST_APPROVE"
    ACCESS_REQUEST_REJECT = "ACCESS_REQUEST_REJECT"
    DEPARTMENT_RESOURCE_ADMINISTER = "DEPARTMENT_RESOURCE_ADMINISTER"
    DEPARTMENT_GRANT_ADMINISTER = "DEPARTMENT_GRANT_ADMINISTER"
    DEPARTMENT_SECURITY_MONITOR = "DEPARTMENT_SECURITY_MONITOR"
    DEPARTMENT_INCIDENT_INVESTIGATE = "DEPARTMENT_INCIDENT_INVESTIGATE"


class ScopeKind(str, Enum):
    ORGANIZATION = "ORGANIZATION"
    DEPARTMENT = "DEPARTMENT"
    ACCESS_REQUEST = "ACCESS_REQUEST"


@dataclass(frozen=True)
class ActionPolicy:
    scope_kind: ScopeKind
    permitted_roles: frozenset[OrganizationRole]


_SUPER_ONLY = frozenset({OrganizationRole.SUPER_ADMIN})
_DEPARTMENT_ADMINS = frozenset({OrganizationRole.SUPER_ADMIN, OrganizationRole.DEPARTMENT_ADMIN})
ACTION_MATRIX = MappingProxyType({
    AdministrativeAction.ORGANIZATION_ADMINISTER: ActionPolicy(ScopeKind.ORGANIZATION, _SUPER_ONLY),
    AdministrativeAction.IDENTITY_ADMINISTER: ActionPolicy(ScopeKind.ORGANIZATION, _SUPER_ONLY),
    AdministrativeAction.DEPARTMENT_ASSIGNMENTS_ADMINISTER: ActionPolicy(ScopeKind.ORGANIZATION, _SUPER_ONLY),
    AdministrativeAction.ORGANIZATION_SECURITY_MONITOR: ActionPolicy(ScopeKind.ORGANIZATION, _SUPER_ONLY),
    AdministrativeAction.DEPARTMENT_ADMINISTER: ActionPolicy(ScopeKind.DEPARTMENT, _DEPARTMENT_ADMINS),
    AdministrativeAction.ACCESS_REQUEST_APPROVE: ActionPolicy(ScopeKind.ACCESS_REQUEST, _DEPARTMENT_ADMINS),
    AdministrativeAction.ACCESS_REQUEST_REJECT: ActionPolicy(ScopeKind.ACCESS_REQUEST, _DEPARTMENT_ADMINS),
    AdministrativeAction.DEPARTMENT_RESOURCE_ADMINISTER: ActionPolicy(ScopeKind.DEPARTMENT, _DEPARTMENT_ADMINS),
    AdministrativeAction.DEPARTMENT_GRANT_ADMINISTER: ActionPolicy(ScopeKind.DEPARTMENT, _DEPARTMENT_ADMINS),
    AdministrativeAction.DEPARTMENT_SECURITY_MONITOR: ActionPolicy(ScopeKind.DEPARTMENT, _DEPARTMENT_ADMINS),
    AdministrativeAction.DEPARTMENT_INCIDENT_INVESTIGATE: ActionPolicy(ScopeKind.DEPARTMENT, _DEPARTMENT_ADMINS),
})


@dataclass(frozen=True)
class OrganizationScope:
    pass


@dataclass(frozen=True)
class DepartmentScope:
    department_id: str


@dataclass(frozen=True)
class AccessRequestScope:
    request_id: str
    expected_department_id: str | None = None


AuthorityScope = OrganizationScope | DepartmentScope | AccessRequestScope


class TrustedPrincipalContext(Protocol):
    """Future authentication adapter contract, not an authentication implementation.

    The issuer must validate identity/session/revocation and, after Unit 6, TOTP
    assurance server-side. Neither this protocol nor a context ID proves assurance.
    Raw request fields and JWT role/assignment claims must never supply policy state.
    """

    @property
    def subject_user_id(self) -> str: ...

    @property
    def authentication_context_id(self) -> str: ...


class AuthorityReason(str, Enum):
    ALLOW_SUPER_ADMIN = "ALLOW_SUPER_ADMIN"
    ALLOW_DEPARTMENT_ASSIGNMENT = "ALLOW_DEPARTMENT_ASSIGNMENT"
    UNKNOWN_ACTION = "UNKNOWN_ACTION"
    UNKNOWN_ACTOR = "UNKNOWN_ACTOR"
    INACTIVE_USER = "INACTIVE_USER"
    INACTIVE_DEPARTMENT = "INACTIVE_DEPARTMENT"
    CANONICAL_ROLE_REQUIRED = "CANONICAL_ROLE_REQUIRED"
    INVALID_CANONICAL_ROLE = "INVALID_CANONICAL_ROLE"
    ROLE_NOT_PERMITTED = "ROLE_NOT_PERMITTED"
    INVALID_SCOPE = "INVALID_SCOPE"
    DEPARTMENT_SCOPE_REQUIRED = "DEPARTMENT_SCOPE_REQUIRED"
    ACCESS_REQUEST_SCOPE_REQUIRED = "ACCESS_REQUEST_SCOPE_REQUIRED"
    SCOPE_NOT_FOUND = "SCOPE_NOT_FOUND"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    DEPARTMENT_ASSIGNMENT_REQUIRED = "DEPARTMENT_ASSIGNMENT_REQUIRED"
    SELF_APPROVAL_PROHIBITED = "SELF_APPROVAL_PROHIBITED"
    TRANSACTION_REQUIRED = "TRANSACTION_REQUIRED"
    UNFLUSHED_STATE = "UNFLUSHED_STATE"


@dataclass(frozen=True)
class AssignmentEvidence:
    assignment_id: str
    department_id: str
    assigned_at: datetime


@dataclass(frozen=True)
class AuthorityDecision:
    allowed: bool
    reason: AuthorityReason
    actor_user_id: str
    action: AdministrativeAction | None
    scope_kind: ScopeKind | None
    required_department_id: str | None = None
    assignment_evidence: AssignmentEvidence | None = None

    @property
    def explanation(self) -> str:
        return {
            AuthorityReason.ALLOW_SUPER_ADMIN: "The active canonical Super Admin may perform this administrative action.",
            AuthorityReason.ALLOW_DEPARTMENT_ASSIGNMENT: "A current explicit assignment permits this department action.",
            AuthorityReason.UNKNOWN_ACTION: "This action is not in the administrative allowlist.",
            AuthorityReason.UNKNOWN_ACTOR: "The actor is not a known user.",
            AuthorityReason.INACTIVE_USER: "Inactive users have no administrative authority.",
            AuthorityReason.INACTIVE_DEPARTMENT: "Inactive departments do not confer departmental authority.",
            AuthorityReason.CANONICAL_ROLE_REQUIRED: "An explicitly mapped canonical organizational role is required.",
            AuthorityReason.INVALID_CANONICAL_ROLE: "The stored canonical role is invalid.",
            AuthorityReason.ROLE_NOT_PERMITTED: "The canonical role does not permit this administrative action.",
            AuthorityReason.INVALID_SCOPE: "The action requires a valid, correctly typed scope.",
            AuthorityReason.DEPARTMENT_SCOPE_REQUIRED: "An explicit department scope is required.",
            AuthorityReason.ACCESS_REQUEST_SCOPE_REQUIRED: "A database-resolved access request scope is required.",
            AuthorityReason.SCOPE_NOT_FOUND: "The required organizational target does not exist.",
            AuthorityReason.SCOPE_MISMATCH: "The actual target department differs from the expected scope.",
            AuthorityReason.DEPARTMENT_ASSIGNMENT_REQUIRED: "No current explicit assignment permits this department action.",
            AuthorityReason.SELF_APPROVAL_PROHIBITED: "No administrator may approve their own access request.",
            AuthorityReason.TRANSACTION_REQUIRED: "Sensitive revalidation requires an explicit caller-owned transaction.",
            AuthorityReason.UNFLUSHED_STATE: "Flush caller changes before transaction-aware authority revalidation.",
        }[self.reason]


def _identifier(value):
    return isinstance(value, str) and bool(value) and value == value.strip() and len(value) <= 36


def _action(value):
    try:
        return AdministrativeAction(value)
    except (ValueError, TypeError):
        return None


def evaluate_authority(session: Session, actor_user_id: str, action: AdministrativeAction,
                       scope: AuthorityScope | None = None) -> AuthorityDecision:
    """Fresh database evaluation; no authentication claim, cache, flush or commit.

    DepartmentScope must name the department derived from the actual server-side
    target. Request scopes are resolved here to prevent omitted/forged requester data.
    A returned decision must not be reused across requests or later transactions.
    """
    action = _action(action)
    policy = ACTION_MATRIX.get(action)

    def decision(reason, department_id=None, evidence=None):
        return AuthorityDecision(
            reason in {AuthorityReason.ALLOW_SUPER_ADMIN, AuthorityReason.ALLOW_DEPARTMENT_ASSIGNMENT},
            reason, actor_user_id, action, policy.scope_kind if policy else None, department_id, evidence,
        )

    if policy is None:
        return decision(AuthorityReason.UNKNOWN_ACTION)
    if not _identifier(actor_user_id):
        return decision(AuthorityReason.UNKNOWN_ACTOR)
    with session.no_autoflush:
        # Scalar SQL deliberately bypasses stale ORM objects and Enum deserialization
        # errors, allowing corrupt/unmapped canonical roles to fail closed explicitly.
        actor = session.execute(select(User.active, cast(User.organization_role, String)).where(
            User.id == actor_user_id,
        )).one_or_none()
        if actor is None:
            return decision(AuthorityReason.UNKNOWN_ACTOR)
        if not actor[0]:
            return decision(AuthorityReason.INACTIVE_USER)
        if actor[1] is None:
            return decision(AuthorityReason.CANONICAL_ROLE_REQUIRED)
        try:
            role = OrganizationRole(actor[1])
        except ValueError:
            return decision(AuthorityReason.INVALID_CANONICAL_ROLE)

        department_id = None
        if policy.scope_kind is ScopeKind.ORGANIZATION:
            if not isinstance(scope, OrganizationScope):
                return decision(AuthorityReason.INVALID_SCOPE)
        elif policy.scope_kind is ScopeKind.ACCESS_REQUEST:
            if not isinstance(scope, AccessRequestScope):
                return decision(AuthorityReason.ACCESS_REQUEST_SCOPE_REQUIRED)
            if (not _identifier(scope.request_id) or
                    (scope.expected_department_id is not None and not _identifier(scope.expected_department_id))):
                return decision(AuthorityReason.INVALID_SCOPE)
            target = session.execute(select(AccessRequest.requester_id, Resource.department_id).join(
                Resource, Resource.id == AccessRequest.resource_id,
            ).join(Department, Department.id == Resource.department_id).where(
                AccessRequest.id == scope.request_id,
            )).one_or_none()
            if target is None:
                return decision(AuthorityReason.SCOPE_NOT_FOUND)
            department_id = target[1]
            if scope.expected_department_id is not None and scope.expected_department_id != department_id:
                return decision(AuthorityReason.SCOPE_MISMATCH)
            if action is AdministrativeAction.ACCESS_REQUEST_APPROVE and target[0] == actor_user_id:
                return decision(AuthorityReason.SELF_APPROVAL_PROHIBITED, department_id)
        else:
            if not isinstance(scope, DepartmentScope):
                return decision(AuthorityReason.DEPARTMENT_SCOPE_REQUIRED)
            if not _identifier(scope.department_id):
                return decision(AuthorityReason.INVALID_SCOPE)
            department_id = session.scalar(select(Department.id).where(Department.id == scope.department_id))
            if department_id is None:
                return decision(AuthorityReason.SCOPE_NOT_FOUND)

        if department_id is not None and not session.scalar(select(Department.active).where(Department.id == department_id)):
            return decision(AuthorityReason.INACTIVE_DEPARTMENT, department_id)
        if role not in policy.permitted_roles:
            return decision(AuthorityReason.ROLE_NOT_PERMITTED, department_id)
        if role is OrganizationRole.SUPER_ADMIN:
            return decision(AuthorityReason.ALLOW_SUPER_ADMIN, department_id)
        assignment = session.execute(select(
            DepartmentAdminAssignment.id, DepartmentAdminAssignment.assigned_at,
        ).where(
            DepartmentAdminAssignment.user_id == actor_user_id,
            DepartmentAdminAssignment.department_id == department_id,
            DepartmentAdminAssignment.revoked_at.is_(None),
            DepartmentAdminAssignment.revoked_by.is_(None),
            DepartmentAdminAssignment.assigned_at <= datetime.now(timezone.utc),
        )).one_or_none()
        if assignment is None:
            return decision(AuthorityReason.DEPARTMENT_ASSIGNMENT_REQUIRED, department_id)
        assigned_at = assignment[1]
        if assigned_at.tzinfo is None:
            assigned_at = assigned_at.replace(tzinfo=timezone.utc)
        return decision(AuthorityReason.ALLOW_DEPARTMENT_ASSIGNMENT, department_id,
                        AssignmentEvidence(assignment[0], department_id, assigned_at))


def revalidate_authority_for_mutation(session: Session, actor_user_id: str,
                                      action: AdministrativeAction,
                                      scope: AuthorityScope | None = None) -> AuthorityDecision:
    """Recheck while holding Unit 2's identity lock until the caller ends its transaction.

    Consumers must derive/lock department-scoped business targets in the same
    transaction, reject DENY, mutate immediately and commit their audit atomically.
    No transaction is opened/committed here, and no stale-state token is bypassed.
    """
    parsed = _action(action)
    policy = ACTION_MATRIX.get(parsed)
    transaction = session.get_transaction()
    if transaction is None or transaction.origin is not SessionTransactionOrigin.BEGIN:
        return AuthorityDecision(False, AuthorityReason.TRANSACTION_REQUIRED, actor_user_id,
                                 parsed, policy.scope_kind if policy else None)
    if session.new or session.dirty or session.deleted:
        return AuthorityDecision(False, AuthorityReason.UNFLUSHED_STATE, actor_user_id,
                                 parsed, policy.scope_kind if policy else None)
    preliminary = evaluate_authority(session, actor_user_id, action, scope)
    if not preliminary.allowed:
        return preliminary
    lock_identity(session, actor_user_id)
    if isinstance(scope, AccessRequestScope):
        resource_id = session.scalar(select(AccessRequest.resource_id).where(
            AccessRequest.id == scope.request_id,
        ).with_for_update())
        if resource_id is not None:
            # Resource metadata is immutable in the current application lifecycle.
            session.execute(select(Resource.id).where(Resource.id == resource_id)).all()
    elif isinstance(scope, DepartmentScope):
        coordination = session.info.get("incident_locked_departments")
        if coordination and coordination[0] is transaction:
            if scope.department_id not in coordination[1]:
                raise RuntimeError("Incident coordination scope changed; abort transaction")
        else:
            session.execute(select(Department.id).where(Department.id == scope.department_id).with_for_update()).all()
    return evaluate_authority(session, actor_user_id, action, scope)
