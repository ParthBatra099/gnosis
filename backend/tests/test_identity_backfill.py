from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from sqlalchemy import event, select
from sqlalchemy.orm import Session

from app.models import AccessGrant, AccessRequest, AuditEvent, DepartmentAdminAssignment, Resource, User
from app.schemas.identity_backfill import IdentityBackfillManifest
from app.services.identity_backfill_service import COMPLETED, VerifiedReview, run_backfill
from app.services.identity_service import IdentityError, read_identity_state
from scripts.migrate_identity_roles import main
from tests.test_identity_service import engine, identity_data


@pytest.fixture
def document(engine, identity_data):
    ids = identity_data
    roles = {"operator": "EMPLOYEE", "reviewer": "SUPER_ADMIN", "target": "DEPARTMENT_ADMIN", "inactive": "EMPLOYEE"}
    with Session(engine) as session:
        users = [{
            "user_id": ids[name], "expected_legacy_role": session.get(User, ids[name]).role,
            "expected_organization_role": None,
            "expected_revision": read_identity_state(session, ids[name]).revision,
            "organization_role": roles[name],
            "department_ids": [ids["hr"], ids["finance"]] if name == "target" else [],
            "revoke_assignment_ids": [],
        } for name in roles]
    return {
        "schema_version": 1, "manifest_id": "FICTIONAL-review", "manifest_version": 1,
        "initial_super_admin_user_id": ids["reviewer"],
        "operator": {"operator_id": "FICTIONAL-operator-directory-id", "user_id": ids["operator"]},
        "reviewer": {"reviewer_id": "FICTIONAL-independent-reviewer", "user_id": ids["reviewer"]},
        "approval_reference": "FICTIONAL-approval-reference", "reason": "Reviewed test fixture only",
        "users": users,
    }


def approval(manifest, engine):
    return VerifiedReview(
        "FICTIONAL-trusted-review-record", manifest.digest(), manifest.reviewer.reviewer_id,
        manifest.reviewer.user_id, manifest.approval_reference, "FICTIONAL-disposable",
        "sqlite:///:memory:", True, datetime.now(timezone.utc) + timedelta(hours=1), engine,
    )


def apply(engine, manifest, **kwargs):
    options = {"environment_id": "FICTIONAL-disposable", "execute": True,
               "confirmation": f"APPLY:{manifest.digest()}",
               "review_verifier": lambda digest, target, supplied_engine: approval(manifest, engine)}
    options.update(kwargs)
    return run_backfill(engine, manifest, **options)


def snapshot(engine):
    with Session(engine) as session:
        return {
            "users": [(u.id, u.role, u.organization_role, u.department_id, u.active, u.password_hash)
                      for u in session.scalars(select(User).order_by(User.id))],
            "assignments": [(a.id, a.user_id, a.department_id, a.assigned_by, a.assigned_at, a.revoked_by, a.revoked_at)
                            for a in session.scalars(select(DepartmentAdminAssignment).order_by(DepartmentAdminAssignment.id))],
            "audits": [(a.id, a.action, a.actor_id, a.context_data)
                       for a in session.scalars(select(AuditEvent).order_by(AuditEvent.id))],
        }


def test_database_dry_run_is_default_and_has_no_writes(engine, document):
    manifest = IdentityBackfillManifest.model_validate(document)
    before = snapshot(engine)
    statements = []

    def capture(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement.strip().split()[0].upper())

    event.listen(engine, "before_cursor_execute", capture)
    try:
        result = run_backfill(engine, manifest, environment_id="FICTIONAL-disposable")
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert result["status"] == "dry_run"
    assert all(item["role_change"] for item in result["changes"])
    assert not ({"UPDATE", "INSERT", "DELETE", "CREATE", "ALTER", "DROP"} & set(statements))
    assert snapshot(engine) == before


def test_explicit_mapping_includes_inactive_and_does_not_promote_legacy_admin(engine, document, identity_data):
    manifest = IdentityBackfillManifest.model_validate(document)
    apply(engine, manifest)
    ids = identity_data
    with Session(engine) as session:
        operator = session.get(User, ids["operator"])
        assert operator.role == "ADMIN" and operator.organization_role == "EMPLOYEE"
        assert session.get(User, ids["reviewer"]).organization_role == "SUPER_ADMIN"
        inactive = session.get(User, ids["inactive"])
        assert not inactive.active and inactive.organization_role == "EMPLOYEE"
        assignments = session.scalars(select(DepartmentAdminAssignment)).all()
        assert {(a.user_id, a.department_id) for a in assignments} == {
            (ids["target"], ids["hr"]), (ids["target"], ids["finance"]),
        }
        assert all(a.assigned_by == ids["operator"] for a in assignments)


@pytest.mark.parametrize("kind", ["missing_inactive", "unknown_user", "unknown_department", "stale_revision", "wrong_legacy"])
def test_invalid_inventory_or_baseline_rolls_back_without_changes(engine, document, identity_data, kind):
    bad = deepcopy(document)
    if kind == "missing_inactive":
        bad["users"] = [u for u in bad["users"] if u["user_id"] != identity_data["inactive"]]
    elif kind == "unknown_user":
        bad["users"][-1]["user_id"] = "fictional-not-a-user"
    elif kind == "unknown_department":
        bad["users"][2]["department_ids"] = ["fictional-not-a-department"]
    elif kind == "stale_revision":
        bad["users"][2]["expected_revision"] = "0" * 64
    else:
        bad["users"][2]["expected_legacy_role"] = "ADMIN"
    manifest = IdentityBackfillManifest.model_validate(bad)
    before = snapshot(engine)
    with pytest.raises(IdentityError):
        apply(engine, manifest)
    assert snapshot(engine) == before


@pytest.mark.parametrize("missing", ["initial_super_admin_user_id", "reviewer", "approval_reference", "operator", "reason", "manifest_id"])
def test_missing_manifest_provenance_is_rejected(document, missing):
    bad = deepcopy(document)
    del bad[missing]
    with pytest.raises(ValidationError):
        IdentityBackfillManifest.model_validate(bad)


@pytest.mark.parametrize("kind", ["initial_unknown", "initial_wrong_role", "duplicate_user", "duplicate_assignment", "invalid_role",
                                  "self_review_user", "self_review_directory", "assignment_to_employee", "extra_field"])
def test_invalid_manifest_contract_is_rejected(document, kind):
    bad = deepcopy(document)
    if kind == "initial_unknown":
        bad["initial_super_admin_user_id"] = "fictional-unknown"
    elif kind == "initial_wrong_role":
        bad["initial_super_admin_user_id"] = bad["operator"]["user_id"]
    elif kind == "duplicate_user":
        bad["users"].append(deepcopy(bad["users"][0]))
    elif kind == "duplicate_assignment":
        bad["users"][2]["department_ids"] *= 2
    elif kind == "invalid_role":
        bad["users"][2]["organization_role"] = "ADMIN"
    elif kind == "self_review_user":
        bad["reviewer"]["user_id"] = bad["operator"]["user_id"]
    elif kind == "self_review_directory":
        bad["reviewer"]["reviewer_id"] = bad["operator"]["operator_id"]
    elif kind == "assignment_to_employee":
        bad["users"][0]["department_ids"] = ["fictional-hr"]
    else:
        bad["password"] = "must-not-be-accepted"
    with pytest.raises(ValidationError):
        IdentityBackfillManifest.model_validate(bad)


@pytest.mark.parametrize("name", ["initial", "operator", "reviewer"])
def test_inactive_execution_principals_are_rejected(engine, document, name):
    user_id = document["initial_super_admin_user_id"] if name == "initial" else document[name]["user_id"]
    with Session(engine) as session, session.begin():
        session.get(User, user_id).active = False
    manifest = IdentityBackfillManifest.model_validate(document)
    with pytest.raises(IdentityError, match="must be active"):
        apply(engine, manifest)


def test_ownership_does_not_generate_assignments(engine, document):
    changed = deepcopy(document)
    changed["users"][2]["organization_role"] = "EMPLOYEE"
    changed["users"][2]["department_ids"] = []
    apply(engine, IdentityBackfillManifest.model_validate(changed))
    with Session(engine) as session:
        assert session.scalar(select(Resource.owner_id)) is not None
        assert session.scalars(select(DepartmentAdminAssignment)).all() == []


@pytest.mark.parametrize("kind", ["confirmation", "no_verifier", "unverified_record", "digest", "reviewer", "reference", "target", "wrong_engine", "not_disposable", "expired", "malformed"])
def test_execution_requires_confirmation_and_trusted_target_bound_review(engine, document, kind):
    manifest = IdentityBackfillManifest.model_validate(document)
    before = snapshot(engine)
    review = approval(manifest, engine)
    kwargs = {}
    if kind == "confirmation":
        kwargs["confirmation"] = "yes"
    elif kind == "no_verifier":
        kwargs["review_verifier"] = None
    else:
        if kind == "unverified_record":
            review = {"approved": True}
        elif kind == "digest":
            review = replace(review, manifest_sha256="0" * 64)
        elif kind == "reviewer":
            review = replace(review, reviewer_user_id=manifest.operator.user_id)
        elif kind == "reference":
            review = replace(review, approval_reference="different")
        elif kind == "target":
            review = replace(review, environment_id="different")
        elif kind == "wrong_engine":
            review = replace(review, database_engine=object())
        elif kind == "not_disposable":
            review = replace(review, disposable=False)
        elif kind == "malformed":
            review = replace(review, expires_at=None)
        else:
            review = replace(review, expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
        kwargs["review_verifier"] = lambda digest, target, supplied_engine: review
    with pytest.raises(IdentityError):
        apply(engine, manifest, **kwargs)
    assert snapshot(engine) == before


@pytest.mark.parametrize("url", ["postgresql+psycopg://localhost/gnosis_db", "sqlite:///project.db", "sqlite:///file:memory?mode=memory&uri=true"])
def test_unsafe_targets_are_rejected_before_any_connection(document, url):
    # No unsafe engine or DBAPI is created, even in the negative test.
    class RejectedEngine:
        dialect = SimpleNamespace(name="sqlite")

        def connect(self):
            raise AssertionError("Unsafe target must never connect")

    target = RejectedEngine()
    target.url = url
    with pytest.raises(IdentityError, match="in-memory"):
        apply(target, IdentityBackfillManifest.model_validate(document))


def test_exact_rerun_has_no_duplicate_audit_or_assignments(engine, document):
    manifest = IdentityBackfillManifest.model_validate(document)
    first = apply(engine, manifest)
    before = snapshot(engine)
    second = apply(engine, manifest)
    assert first["status"] == "applied" and second["status"] == "already_applied"
    assert first["receipt_id"] == second["receipt_id"]
    assert snapshot(engine) == before


@pytest.mark.parametrize("failure", ["middle_audit", "receipt", "interrupt"])
def test_interruption_rolls_back_entire_manifest_and_rerun_succeeds(engine, document, failure):
    manifest = IdentityBackfillManifest.model_validate(document)
    before = snapshot(engine)
    seen = []

    def fail(mapper, connection, audit):
        seen.append(audit.action)
        if (failure == "receipt" and audit.action == COMPLETED) or (failure != "receipt" and len(seen) == 3):
            if failure == "interrupt":
                raise KeyboardInterrupt("Injected interruption")
            raise RuntimeError("Injected backfill failure")

    event.listen(AuditEvent, "before_insert", fail)
    try:
        with pytest.raises(KeyboardInterrupt if failure == "interrupt" else RuntimeError):
            apply(engine, manifest)
    finally:
        event.remove(AuditEvent, "before_insert", fail)
    assert snapshot(engine) == before
    assert apply(engine, manifest)["status"] == "applied"


def test_completed_manifest_cannot_be_reused_with_modified_mapping(engine, document):
    manifest = IdentityBackfillManifest.model_validate(document)
    apply(engine, manifest)
    changed = deepcopy(document)
    changed["users"][2]["department_ids"] = []
    with pytest.raises(IdentityError, match="different content"):
        apply(engine, IdentityBackfillManifest.model_validate(changed))


def next_manifest(engine, document):
    changed = deepcopy(document)
    changed["manifest_version"] += 1
    with Session(engine) as session:
        for mapping in changed["users"]:
            state = read_identity_state(session, mapping["user_id"])
            mapping["expected_organization_role"] = state.organization_role
            mapping["expected_revision"] = state.revision
    return changed


def test_new_reviewed_manifest_explicitly_revokes_assignments_before_demotion(engine, document):
    apply(engine, IdentityBackfillManifest.model_validate(document))
    changed = next_manifest(engine, document)
    target = changed["users"][2]
    target["organization_role"] = "EMPLOYEE"
    target["department_ids"] = []
    with Session(engine) as session:
        assignment_ids = session.scalars(select(DepartmentAdminAssignment.id)).all()
    target["revoke_assignment_ids"] = assignment_ids
    manifest = IdentityBackfillManifest.model_validate(changed)
    assert apply(engine, manifest)["status"] == "applied"
    with Session(engine) as session:
        assert session.get(User, target["user_id"]).organization_role == "EMPLOYEE"
        history = session.scalars(select(DepartmentAdminAssignment)).all()
        assert {a.id for a in history} == set(assignment_ids)
        assert all(a.revoked_at is not None for a in history)
        assert len(session.scalars(select(AuditEvent).where(AuditEvent.action == "DEPARTMENT_ADMIN_REVOKED")).all()) == 2
    assert apply(engine, manifest)["status"] == "already_applied"


@pytest.mark.parametrize("revocations", [[], ["fictional-unknown-assignment"]])
def test_assignment_removal_cannot_be_inferred_from_missing_desired_department(engine, document, revocations):
    apply(engine, IdentityBackfillManifest.model_validate(document))
    changed = next_manifest(engine, document)
    changed["users"][2]["department_ids"] = []
    changed["users"][2]["revoke_assignment_ids"] = revocations
    before = snapshot(engine)
    with pytest.raises(IdentityError, match="explicit revocation"):
        apply(engine, IdentityBackfillManifest.model_validate(changed))
    assert snapshot(engine) == before


def test_old_receipt_cannot_restore_identity_after_later_changes(engine, document):
    manifest = IdentityBackfillManifest.model_validate(document)
    apply(engine, manifest)
    changed = next_manifest(engine, document)
    changed["users"][0]["organization_role"] = "SUPER_ADMIN"
    apply(engine, IdentityBackfillManifest.model_validate(changed))
    before = snapshot(engine)
    with pytest.raises(IdentityError, match="changed after completed"):
        apply(engine, manifest)
    assert snapshot(engine) == before


def test_business_records_and_legacy_identity_are_preserved(engine, document):
    before = snapshot(engine)
    apply(engine, IdentityBackfillManifest.model_validate(document))
    after = snapshot(engine)
    assert [(u[0], u[1], *u[3:]) for u in before["users"]] == [(u[0], u[1], *u[3:]) for u in after["users"]]
    assert before["audits"][0] in after["audits"]
    with Session(engine) as session:
        assert session.get(Resource, "fictional-resource").owner_id == "fictional-target"
        assert session.get(AccessRequest, "fictional-request").reason == "Existing reason"
        assert session.get(AccessGrant, "fictional-grant").access_request_id == "fictional-request"
        receipt = session.scalar(select(AuditEvent).where(AuditEvent.action == COMPLETED))
        assert receipt.context_data["manifest_sha256"] == IdentityBackfillManifest.model_validate(document).digest()
        assert "DO_NOT_AUDIT_HASH" not in json.dumps([a[3] for a in after["audits"]])


def test_cli_defaults_to_offline_validation_and_cannot_self_configure_execution(document, monkeypatch, capsys):
    monkeypatch.setattr(Path, "read_text", lambda self, **kwargs: json.dumps(document))
    path = str(Path(__file__).resolve().parents[1] / "fictional-not-created.json")
    assert main(["--manifest", path]) == 0
    output = json.loads(capsys.readouterr().out)
    assert not output["database_coverage_verified"] and not output["execution_authorized"]
    assert main(["--manifest", path, "--execute", "--database-url", "sqlite:///:memory:",
                 "--environment-id", "FICTIONAL-disposable", "--confirm", f"APPLY:{output['manifest_sha256']}"]) == 2


def test_cli_rejects_project_target_even_for_offline_dry_run(document, monkeypatch):
    monkeypatch.setattr(Path, "read_text", lambda self, **kwargs: json.dumps(document))
    path = str(Path(__file__).resolve().parents[1] / "fictional-not-created.json")
    assert main(["--manifest", path, "--database-url", "postgresql+psycopg://localhost/gnosis_db"]) == 2


def test_duplicate_json_keys_are_not_silently_overwritten(document):
    encoded = json.dumps(document)
    conflicting = '{"initial_super_admin_user_id":"FICTIONAL-conflict",' + encoded[1:]
    with pytest.raises(ValueError, match="Duplicate JSON key"):
        IdentityBackfillManifest.from_json(conflicting)


def test_documented_example_is_valid_but_clearly_fictional():
    content = (Path(__file__).resolve().parents[1] / "docs/identity_backfill.md").read_text(encoding="utf-8")
    encoded = content.split("```json\n", 1)[1].split("```", 1)[0]
    manifest = IdentityBackfillManifest.from_json(encoded)
    assert manifest.manifest_id.startswith("FICTIONAL")
    assert all(mapping.user_id.startswith("FICTIONAL") for mapping in manifest.users)
    assert all(mapping.expected_revision == "0" * 64 for mapping in manifest.users)
