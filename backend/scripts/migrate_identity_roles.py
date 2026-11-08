"""Offline manifest validation by default. Never opens the configured project DB.

The CLI has no trusted approval integration or prepared disposable engine, so its
execution mode fails closed. Trusted hosts/tests may inject both into ``main``.
"""

import argparse
import json
from pathlib import Path
import sys


def main(argv=None, *, engine=None, review_verifier=None):
    workspace = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(workspace / "backend"))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, help="Reviewed manifest JSON inside the workspace")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--environment-id")
    parser.add_argument("--database-url")
    parser.add_argument("--confirm")
    args = parser.parse_args(argv)
    try:
        from app.schemas.identity_backfill import IdentityBackfillManifest

        path = Path(args.manifest).resolve()
        if not path.is_relative_to(workspace):
            raise ValueError("Manifest must be inside the project workspace")
        manifest = IdentityBackfillManifest.from_json(path.read_text(encoding="utf-8"))
        if args.database_url is not None and args.database_url != "sqlite:///:memory:":
            raise ValueError("Only explicitly approved in-memory SQLite targets are supported")
        if not args.execute:
            # Schema/provenance structure only; no application DB imports or connections.
            print(json.dumps({"status": "offline_dry_run", "manifest_sha256": manifest.digest(),
                              "database_coverage_verified": False, "execution_authorized": False}))
            return 0
        if args.confirm != f"APPLY:{manifest.digest()}":
            raise ValueError("Execution requires exact APPLY:<manifest_sha256> confirmation")
        if args.database_url != "sqlite:///:memory:" or not args.environment_id:
            raise ValueError("An explicit disposable database target and environment ID are required")
        if engine is None or review_verifier is None:
            raise ValueError("Trusted review verifier and prepared disposable engine are required; CLI execution disabled")
        from app.services.identity_backfill_service import run_backfill

        result = run_backfill(engine, manifest, environment_id=args.environment_id,
                              execute=True, confirmation=args.confirm, review_verifier=review_verifier)
        print(json.dumps(result))
        return 0
    except (ValueError, OSError) as error:
        # Never echo manifest contents, SQL parameters, or validation input values.
        print(f"Backfill rejected ({type(error).__name__}); check manifest, baseline and execution safeguards.",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
