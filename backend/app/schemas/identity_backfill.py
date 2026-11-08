"""Reviewable backfill documents. Claimed reviewer fields are not authentication."""

import hashlib
import json
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from app.core.constants import OrganizationRole

Identifier = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class StrictDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Operator(StrictDocument):
    operator_id: Identifier
    user_id: Identifier


class Reviewer(StrictDocument):
    reviewer_id: Identifier
    user_id: Identifier


class UserMapping(StrictDocument):
    user_id: Identifier
    expected_legacy_role: Identifier
    expected_organization_role: OrganizationRole | None
    expected_revision: Digest
    organization_role: OrganizationRole
    department_ids: list[Identifier]
    revoke_assignment_ids: list[Identifier]

    @model_validator(mode="after")
    def check_assignments(self):
        if len(self.department_ids) != len(set(self.department_ids)):
            raise ValueError("Duplicate department assignment")
        if len(self.revoke_assignment_ids) != len(set(self.revoke_assignment_ids)):
            raise ValueError("Duplicate assignment revocation")
        if self.department_ids and self.organization_role is not OrganizationRole.DEPARTMENT_ADMIN:
            raise ValueError("Only DEPARTMENT_ADMIN mappings may contain assignments")
        return self


class IdentityBackfillManifest(StrictDocument):
    schema_version: Literal[1]
    manifest_id: Identifier
    manifest_version: int = Field(strict=True, ge=1)
    initial_super_admin_user_id: Identifier
    operator: Operator
    reviewer: Reviewer
    approval_reference: Identifier
    reason: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2000)]
    users: list[UserMapping] = Field(min_length=1)

    @model_validator(mode="after")
    def check_identity_contract(self):
        users = {user.user_id: user for user in self.users}
        if len(users) != len(self.users):
            raise ValueError("Duplicate user mapping")
        initial = users.get(self.initial_super_admin_user_id)
        if initial is None or initial.organization_role is not OrganizationRole.SUPER_ADMIN:
            raise ValueError("Initial Super Admin must be explicitly mapped to SUPER_ADMIN")
        if self.operator.user_id == self.reviewer.user_id or self.operator.operator_id == self.reviewer.reviewer_id:
            raise ValueError("Operator and independent reviewer must be different identities")
        if self.operator.user_id not in users or self.reviewer.user_id not in users:
            raise ValueError("Operator and reviewer must be explicitly included in user mappings")
        return self

    def digest(self):
        canonical = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    @classmethod
    def from_json(cls, document):
        def unique_keys(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("Duplicate JSON key in manifest")
                result[key] = value
            return result

        return cls.model_validate(json.loads(document, object_pairs_hook=unique_keys))
