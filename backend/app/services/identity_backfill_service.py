"""Reviewed, all-or-nothing backfill for explicitly approved in-memory sandboxes.

The verifier is an external trust boundary, not a reviewer name in operator JSON.
No database engines, schemas, sessions for authentication, or credentials are created.
"""

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.constants import OrganizationRole
from app.models import AuditEvent, Department, DepartmentAdminAssignment, User
from app.schemas.identity_backfill import IdentityBackfillManifest
from app.services.identity_service import (
    IdentityError, IdentityEvidence, change_organization_role,
    create_department_admin_assignment, lock_identity, read_identity_state,
    revoke_department_admin_assignment,
)

COMPLETED = "IDENTITY_BACKFILL_COMPLETED"


@dataclass(frozen=True)
class VerifiedReview:
    """Only a trusted integration may issue this after authenticating approval."""

    approval_record_id: str
    manifest_sha256: str
    reviewer_id: str
    reviewer_user_id: str
    approval_reference: str
    environment_id: str
    database_url: str
    disposable: bool
    expires_at: datetime
    database_engine: object


def _check_target(engine, environment_id):
    if not environment_id or not environment_id.strip():
        raise IdentityError("An explicit disposable environment identifier is required")
    # Unit 2 does not authorize any network database, file database or project URL.
    if str(engine.url) != "sqlite:///:memory:" or engine.dialect.name != "sqlite":
        raise IdentityError("Only explicitly approved in-memory SQLite targets are supported")


def _check_review(manifest, engine, environment_id, confirmation, verifier):
    digest = manifest.digest()
    if confirmation != f"APPLY:{digest}":
        raise IdentityError("Execution requires the exact APPLY:<manifest_sha256> confirmation")
    if verifier is None:
        raise IdentityError("No trusted independent review verifier is configured; execution disabled")
    review = verifier(digest, environment_id, engine)
    if not isinstance(review, VerifiedReview):
        raise IdentityError("Verifier did not supply a verified approval record")
    identifiers = (review.approval_record_id, review.manifest_sha256, review.reviewer_id,
                   review.reviewer_user_id, review.approval_reference, review.environment_id, review.database_url)
    if (not all(isinstance(value, str) and value.strip() for value in identifiers)
            or not isinstance(review.expires_at, datetime)):
        raise IdentityError("Verifier supplied malformed approval evidence")
    if (
        not review.approval_record_id.strip()
        or review.manifest_sha256 != digest
        or review.reviewer_id != manifest.reviewer.reviewer_id
        or review.reviewer_user_id != manifest.reviewer.user_id
        or review.approval_reference != manifest.approval_reference
        or review.environment_id != environment_id
        or review.database_url != str(engine.url)
        or review.database_engine is not engine
        or review.disposable is not True
        or review.expires_at.tzinfo is None
        or review.expires_at <= datetime.now(timezone.utc)
    ):
        raise IdentityError("Independent approval does not match manifest and disposable target")
    return review


def _inventory(session, manifest):
    users = {u.id: u for u in session.scalars(select(User).order_by(User.id)).all()}
    mapped = {u.user_id for u in manifest.users}
    if mapped != set(users):
        raise IdentityError("Manifest must map every existing user, including inactive users, and no unknown users")
    for user_id in (manifest.initial_super_admin_user_id, manifest.operator.user_id, manifest.reviewer.user_id):
        if not users[user_id].active:
            raise IdentityError("Initial Super Admin, operator and reviewer must be active existing users")
    departments = set(session.scalars(select(Department.id)).all())
    if any(set(mapping.department_ids) - departments for mapping in manifest.users):
        raise IdentityError("Manifest references an unknown department")
    return users


def _receipt(session, manifest):
    receipts = session.scalars(select(AuditEvent).where(
        AuditEvent.action == COMPLETED,
        AuditEvent.context_data["manifest_id"].as_string() == manifest.manifest_id,
        AuditEvent.context_data["manifest_version"].as_string() == str(manifest.manifest_version),
    )).all()
    if len(receipts) > 1:
        raise IdentityError("Conflicting backfill completion evidence")
    if not receipts:
        return None
    receipt = receipts[0]
    if receipt.context_data.get("manifest_sha256") != manifest.digest():
        raise IdentityError("Manifest identifier/version was already used with different content")
    for mapping in manifest.users:
        state = read_identity_state(session, mapping.user_id)
        if state.revision != receipt.context_data["final_revisions"].get(mapping.user_id):
            raise IdentityError("Identity changed after completed backfill; a new reviewed manifest is required")
    return receipt


def _plan(session, manifest, users):
    plan = []
    for mapping in sorted(manifest.users, key=lambda item: item.user_id):
        current = users[mapping.user_id]
        state = read_identity_state(session, mapping.user_id)
        if (current.role != mapping.expected_legacy_role
                or state.organization_role != mapping.expected_organization_role
                or state.revision != mapping.expected_revision):
            raise IdentityError("Identity differs from the reviewed baseline")
        active = session.scalars(select(DepartmentAdminAssignment).where(
            DepartmentAdminAssignment.user_id == mapping.user_id,
            DepartmentAdminAssignment.revoked_at.is_(None),
        )).all()
        revoke = {a.id for a in active if a.department_id not in mapping.department_ids}
        if revoke != set(mapping.revoke_assignment_ids):
            raise IdentityError("Existing assignments require exact, explicit revocation identifiers")
        plan.append({
            "user_id": mapping.user_id,
            "role_change": state.organization_role != mapping.organization_role,
            "revoke_assignment_ids": sorted(revoke),
            "create_department_ids": sorted(set(mapping.department_ids) - {a.department_id for a in active}),
        })
    return plan


def run_backfill(engine, manifest: IdentityBackfillManifest, *, environment_id,
                 execute=False, confirmation=None, review_verifier=None):
    """Dry-run by default. Execution requires trusted approval and explicit confirmation.

    The whole manifest (all roles, assignments and completion evidence) is one
    transaction. Interruption rolls it all back. An exact completed rerun is a no-op.
    Caller must quiesce user/department creation during execution; no schema or
    application-maintenance infrastructure is introduced in this unit.
    """
    # Revalidate even a mutable model's nested lists before trusting its digest.
    manifest = IdentityBackfillManifest.model_validate(manifest.model_dump(mode="json"))
    _check_target(engine, environment_id)
    review = _check_review(manifest, engine, environment_id, confirmation, review_verifier) if execute else None
    with Session(engine, autoflush=False) as session:
        with session.begin():
            databases = session.connection().exec_driver_sql("PRAGMA database_list").all()
            if any(row[2] for row in databases):
                raise IdentityError("Disposable connection contains a file-backed or attached database")
            # All cooperating writers lock the same rows in stable order.
            if execute:
                for user_id in sorted(mapping.user_id for mapping in manifest.users):
                    lock_identity(session, user_id)
            users = _inventory(session, manifest)
            receipt = _receipt(session, manifest)
            if receipt:
                return {"status": "already_applied", "manifest_sha256": manifest.digest(),
                        "receipt_id": receipt.id}
            plan = _plan(session, manifest, users)
            if not execute:
                return {"status": "dry_run", "manifest_sha256": manifest.digest(), "changes": plan}

            evidence = IdentityEvidence(manifest.operator.user_id, manifest.reason, {
                "manifest_id": manifest.manifest_id, "manifest_version": str(manifest.manifest_version),
                "manifest_sha256": manifest.digest(), "operator_id": manifest.operator.operator_id,
                "reviewer_id": manifest.reviewer.reviewer_id, "reviewer_user_id": manifest.reviewer.user_id,
                "approval_reference": manifest.approval_reference,
                "approval_record_id": review.approval_record_id, "environment_id": environment_id,
            })
            changes = {item["user_id"]: item for item in plan}
            for mapping in sorted(manifest.users, key=lambda item: item.user_id):
                for assignment_id in changes[mapping.user_id]["revoke_assignment_ids"]:
                    revoke_department_admin_assignment(
                        session, mapping.user_id, assignment_id,
                        expected_revision=read_identity_state(session, mapping.user_id).revision,
                        evidence=evidence,
                    )
                change_organization_role(
                    session, mapping.user_id, mapping.organization_role,
                    expected_revision=read_identity_state(session, mapping.user_id).revision, evidence=evidence,
                )
                for department_id in changes[mapping.user_id]["create_department_ids"]:
                    create_department_admin_assignment(
                        session, mapping.user_id, department_id,
                        expected_revision=read_identity_state(session, mapping.user_id).revision,
                        evidence=evidence,
                    )
            final_revisions = {m.user_id: read_identity_state(session, m.user_id).revision for m in manifest.users}
            now = datetime.now(timezone.utc)
            receipt = AuditEvent(
                actor_id=evidence.actor_id, action=COMPLETED, outcome="ALLOW", reason="REVIEWED_BACKFILL",
                timestamp=now, context_data={**dict(evidence.provenance), "reason": evidence.reason,
                    "initial_super_admin_user_id": manifest.initial_super_admin_user_id,
                    "final_revisions": final_revisions, "completed_at": now.isoformat()},
            )
            session.add(receipt)
            session.flush()
            receipt_id = receipt.id
        return {"status": "applied", "manifest_sha256": manifest.digest(), "receipt_id": receipt_id}
