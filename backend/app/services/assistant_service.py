from dataclasses import dataclass, field
import re
from typing import List
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.resource import Resource
from app.models.access_request import AccessRequest
from app.models.access_grant import AccessGrant
from app.security.access_decision import evaluate_access

# Must match access_decision.SUPPORTED_PERMISSIONS exactly (lowercase).
READ_PERMISSION = "read"

# Single response for "does not exist" AND "not authorized" so neither existence
# nor metadata of unauthorized resources can be inferred.
NO_INFO_MESSAGE = "No relevant information was found."

# Own-data / listing phrasing that must NOT be treated as a resource name.
_OWN_DATA_PATTERN = re.compile(
    r"\bmy\s+(?:(?:pending|active|access)\s+)*"
    r"(?:resources?|requests?|grants?|permissions?|access|profile|department|role|info)\b"
    r"|\bwhat resources\b|\blist resources\b|\bwho am i\b"
    r"|\baccess (?:requests?|grants?)\b|\bpending requests?\b"
    r"|\bactive access\b|\bapproval status\b"
)

# Filler words that may be captured at the start of a resource name.
_LEADING_FILLER = re.compile(r"^(?:(?:me|us|the|my|a|an|to|about|of)\s+)+")


@dataclass
class AssistantQueryResult:
    answer: str
    sources: List[str] = field(default_factory=list)
    access_denied: bool = False


class AssistantService:
    @staticmethod
    def _load_user_grants(db: Session, user: User) -> List[AccessGrant]:
        # evaluate_access is pure (no DB access) and itself checks user_id, resource_id,
        # permission, revoked_at and expires_at, so we just supply this user's grants.
        return db.query(AccessGrant).filter(AccessGrant.user_id == user.id).all()

    @staticmethod
    def _authorized_resources(db: Session, user: User) -> List[Resource]:
        """All resources the user may read, decided solely by evaluate_access."""
        resources = (
            db.query(Resource).order_by(Resource.name.asc(), Resource.id.asc()).all()
        )
        grants = AssistantService._load_user_grants(db, user)
        return [
            r
            for r in resources
            if evaluate_access(user, r, READ_PERMISSION, grants).allowed
        ]

    @staticmethod
    def process_query(db: Session, user: User, query: str) -> AssistantQueryResult:
        """
        Process employee natural language query using conservative, deterministic intent matching.
        Strictly enforces authorization via evaluate_access without side-effect audit pollution.
        """
        q = query.strip().lower()

        # Specific Resource Query (e.g., "Can I access Project Titan?", "Tell me about Financial Report")
        specific_resource_match = re.search(
            r"\b(?:about|access|view|show|read|get)\s+([a-zA-Z0-9_\-\s]+)", q
        )
        if specific_resource_match and not _OWN_DATA_PATTERN.search(q):
            candidate_name = specific_resource_match.group(1).strip()
            candidate_name = _LEADING_FILLER.sub("", candidate_name)
            candidate_name = re.sub(
                r"\b(resource|catalog|file|document)\b", "", candidate_name
            ).strip()
            if candidate_name:
                return AssistantService._handle_specific_resource_query(
                    db, user, candidate_name
                )

        # Intent 1: General Resource Listing ("What resources can I access?", "List my resources")
        if any(
            keyword in q
            for keyword in [
                "resource",
                "catalog",
                "accessible resources",
                "available resources",
            ]
        ):
            return AssistantService._handle_resource_list_query(db, user)

        # Intent 2: Own Access Requests ("What are my access requests?", "Show my pending requests")
        if any(
            keyword in q
            for keyword in ["request", "pending requests", "my requests", "approval status"]
        ):
            return AssistantService._handle_access_requests_query(db, user)

        # Intent 3: Own Active Grants ("Show my active access grants", "My permissions")
        if any(
            keyword in q
            for keyword in ["grant", "permission", "my access", "active access"]
        ):
            return AssistantService._handle_access_grants_query(db, user)

        # Intent 4: Own Profile ("Who am I", "My profile", "My department")
        if any(
            keyword in q
            for keyword in ["profile", "my department", "who am i", "my role", "my info"]
        ):
            return AssistantService._handle_profile_query(user)

        # Intent 5: Unsupported Query
        return AssistantQueryResult(
            answer="This query is not currently supported by GNOSIS. Try asking about accessible resources, a specific resource name, your access requests, or your active grants.",
            sources=[],
            access_denied=False,
        )

    @staticmethod
    def _handle_specific_resource_query(
        db: Session, user: User, target_name: str
    ) -> AssistantQueryResult:
        # Match ONLY among resources the user is authorized to read. A nonexistent
        # resource and an unauthorized one are therefore indistinguishable, and an
        # unauthorized match can no longer shadow an authorized one.
        target = target_name.lower()
        authorized = AssistantService._authorized_resources(db, user)

        target_resource = next((r for r in authorized if r.name.lower() == target), None)
        if target_resource is None:
            target_resource = next(
                (r for r in authorized if target in r.name.lower()), None
            )

        if target_resource is None:
            return AssistantQueryResult(
                answer=NO_INFO_MESSAGE,
                sources=[],
                access_denied=False,
            )

        desc = (
            f" Description: {target_resource.description}"
            if target_resource.description
            else ""
        )
        return AssistantQueryResult(
            answer=f"Resource '{target_resource.name}' ({target_resource.sensitivity}).{desc}",
            sources=[f"Resource:{target_resource.id}"],
            access_denied=False,
        )

    @staticmethod
    def _handle_resource_list_query(db: Session, user: User) -> AssistantQueryResult:
        authorized_resources = AssistantService._authorized_resources(db, user)

        if not authorized_resources:
            return AssistantQueryResult(
                answer=NO_INFO_MESSAGE,
                sources=[],
                access_denied=False,
            )

        resource_names = ", ".join(
            f"'{r.name}' ({r.sensitivity})" for r in authorized_resources
        )
        sources = [f"Resource:{r.id}" for r in authorized_resources]
        return AssistantQueryResult(
            answer=f"You have authorized access to the following resources: {resource_names}.",
            sources=sources,
            access_denied=False,
        )

    @staticmethod
    def _handle_access_requests_query(db: Session, user: User) -> AssistantQueryResult:
        requests = (
            db.query(AccessRequest)
            .filter(AccessRequest.requester_id == user.id)
            .order_by(AccessRequest.created_at.desc())
            .all()
        )

        if not requests:
            return AssistantQueryResult(
                answer="You have not submitted any access requests.",
                sources=[],
                access_denied=False,
            )

        request_summaries = []
        sources = []
        for req in requests:
            resource = db.query(Resource).filter(Resource.id == req.resource_id).first()
            resource_label = resource.name if resource else "Requested Resource"
            request_summaries.append(
                f"Request for '{resource_label}' ({req.permission}) - Status: {req.status}"
            )
            sources.append(f"AccessRequest:{req.id}")

        summary_text = "; ".join(request_summaries)
        return AssistantQueryResult(
            answer=f"Your submitted access requests: {summary_text}.",
            sources=sources,
            access_denied=False,
        )

    @staticmethod
    def _handle_access_grants_query(db: Session, user: User) -> AssistantQueryResult:
        grants = (
            db.query(AccessGrant)
            .filter(AccessGrant.user_id == user.id)
            .order_by(AccessGrant.granted_at.desc())
            .all()
        )

        if not grants:
            return AssistantQueryResult(
                answer="You currently have no active explicit access grants assigned.",
                sources=[],
                access_denied=False,
            )

        grant_summaries = []
        sources = []
        for grant in grants:
            resource = db.query(Resource).filter(Resource.id == grant.resource_id).first()
            resource_name = resource.name if resource else "Granted Resource"
            grant_summaries.append(f"Grant for '{resource_name}'")
            sources.append(f"AccessGrant:{grant.id}")

        summary_text = ", ".join(grant_summaries)
        return AssistantQueryResult(
            answer=f"Your active access grants: {summary_text}.",
            sources=sources,
            access_denied=False,
        )

    @staticmethod
    def _handle_profile_query(user: User) -> AssistantQueryResult:
        return AssistantQueryResult(
            answer=f"User Profile: Name = {user.name}, Email = {user.email}, Role = {user.role}.",
            sources=[f"User:{user.id}"],
            access_denied=False,
        )