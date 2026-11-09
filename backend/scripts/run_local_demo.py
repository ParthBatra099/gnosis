"""Explicit loopback HTTPS launcher / dry-run-first identity bootstrap.

No app imports until explicit arguments and a private configuration are selected.
"""
import argparse
import base64
import getpass
from pathlib import Path
import secrets
import sys
from types import ModuleType, SimpleNamespace


def install_demo_configuration():
    """Fresh-process configuration adapter; never evaluates normal config.py.

    Business modules import only settings. Refuse installation in an already
    initialized application, rather than replacing configuration under live code.
    """
    if "app.core.config" in sys.modules or "app.core.database" in sys.modules:
        raise ValueError("Demo launcher requires a fresh process")
    from pydantic import SecretStr
    module = ModuleType("app.core.config")
    module.settings = SimpleNamespace(
        PROJECT_NAME="GNOSIS LOCAL DEMO", ENVIRONMENT="local-demo", DEBUG=False,
        DATABASE_URL="sqlite:///:memory:", JWT_SECRET_KEY=secrets.token_urlsafe(48), JWT_ALGORITHM="HS256",
        ACCESS_TOKEN_EXPIRE_MINUTES=30, AUTH_SESSION_ABSOLUTE_SECONDS=1800, AUTH_SESSION_IDLE_SECONDS=900,
        AUTH_CHALLENGE_LIFETIME_SECONDS=300, AUTH_CHALLENGE_MAX_ATTEMPTS=5, AUTH_VERIFICATION_MAX_AGE_SECONDS=60,
        AUTH_RATE_LIMIT_WINDOW_SECONDS=300, AUTH_RATE_LIMIT_THRESHOLD=5,
        AUTH_SOURCE_RATE_LIMIT_THRESHOLD=60, AUTH_CSRF_LIFETIME_SECONDS=600,
        AUTH_RATE_LIMIT_KEY=SecretStr(base64.b64encode(secrets.token_bytes(32)).decode()),
        AUTH_CSRF_KEY=SecretStr(base64.b64encode(secrets.token_bytes(32)).decode()),
        AUTH_ALLOWED_ORIGINS=[], AUTH_TRUSTED_PROXY_CIDRS=[], AUTH_ALLOW_BEARER_SESSIONS=False,
        MFA_ENCRYPTION_KEYS=None, MFA_ENCRYPTION_ACTIVE_KEY_VERSION=None, MFA_TOTP_ISSUER="GNOSIS",
        MFA_TOTP_INTERVAL_SECONDS=30, MFA_TOTP_CLOCK_SKEW_STEPS=1, MFA_RECOVERY_CODE_COUNT=10)
    sys.modules[module.__name__] = module
    return module.settings


def demo_engine_options():
    # PostgreSQL connection establishment and all statements/row-lock waits are
    # bounded. No server configuration or ordinary database is changed.
    return dict(echo=False, hide_parameters=True, pool_size=5, max_overflow=0, pool_timeout=5,
                connect_args={"connect_timeout": 5,
                              "options": "-c statement_timeout=5000 -c lock_timeout=3000 -c idle_in_transaction_session_timeout=60000"})


def parser():
    result = argparse.ArgumentParser(description="GNOSIS LOCAL DEMO — password-only, fictional identities")
    result.add_argument("command", choices=["serve", "bootstrap", "verify-existing"])
    result.add_argument("--local-demo", action="store_true", required=True)
    result.add_argument("--ack-password-only-demo", action="store_true", required=True)
    result.add_argument("--target", type=Path, required=True)
    result.add_argument("--manifest", type=Path, required=True)
    result.add_argument("--apply-confirmation")
    result.add_argument("--operator")
    result.add_argument("--origin", action="append")
    result.add_argument("--port", type=int, default=8443)
    result.add_argument("--tls-cert", type=Path)
    result.add_argument("--tls-key", type=Path)
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    if not sys.stdin.isatty():
        raise ValueError("Interactive terminal required; credential input must not fall back to echoed stdin")
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    install_demo_configuration()
    from app.services.demo_bootstrap import DemoManifest, DemoTarget, bootstrap, verify_existing, verify_target
    manifest = DemoManifest.model_validate_json(args.manifest.read_text(encoding="utf-8"))
    target = DemoTarget.model_validate_json(args.target.read_text(encoding="utf-8"))
    if args.command == "serve" and (not args.origin or not args.tls_cert or not args.tls_key
                                    or not 1 <= args.port <= 65535):
        raise ValueError("Explicit HTTPS origin, TLS certificate/key and valid port required")
    if args.apply_confirmation and args.command != "bootstrap":
        raise ValueError("Apply confirmation is only valid for bootstrap")
    if args.command == "bootstrap" and args.apply_confirmation not in (None, "APPLY:" + str(target.instance_id)):
        raise ValueError("Apply confirmation must match the exact demo instance")
    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import URL
    from sqlalchemy.orm import Session
    # The explicitly supplied target, never DATABASE_URL, chooses the connection.
    password = getpass.getpass("Disposable demo PostgreSQL role password: ")
    url = URL.create("postgresql+psycopg", username=target.database_role, password=password,
                     host=target.host, port=target.port, database=target.database)
    bind = create_engine(url, **demo_engine_options())
    try:
        with Session(bind, autoflush=False) as db, db.begin():
            verify_target(db, target)
            if args.command == "bootstrap":
                # Cooperating launchers serialize without adding schema objects.
                db.execute(text("SELECT pg_advisory_xact_lock(1196314447)"))
                bootstrap(db, manifest, target, operator=args.operator)
            else:
                verify_existing(db, manifest, target)
        if args.apply_confirmation:
            # Never hold a connection/transaction during interactive prompts.
            passwords = {}
            try:
                for user in manifest.users:
                    first = getpass.getpass(f"Password for fictional {user.email}: ")
                    if first != getpass.getpass("Repeat password: "):
                        raise ValueError("Password confirmation mismatch")
                    passwords[str(user.id)] = first
                with Session(bind, autoflush=False) as db, db.begin():
                    verify_target(db, target)
                    db.execute(text("SELECT pg_advisory_xact_lock(1196314447)"))
                    bootstrap(db, manifest, target, operator=args.operator, passwords=passwords)
            finally:
                passwords.clear()
        if args.command != "serve":
            print("Demo bootstrap APPLIED" if args.apply_confirmation else "Demo validation PASSED (no identity writes)")
            return 0
        from app.demo_app import create_demo_app
        import uvicorn
        app = create_demo_app(local_demo=True, acknowledge_password_only=True, bind=bind,
                              manifest=manifest, target=target, origins=args.origin)
        print("DEMO MODE — Password-only authentication for fictional local accounts. MFA is not being demonstrated.")
        uvicorn.run(app, host="127.0.0.1", port=args.port, workers=1, reload=False,
                    proxy_headers=False, ssl_certfile=str(args.tls_cert), ssl_keyfile=str(args.tls_key),
                    access_log=False)
    finally:
        bind.dispose()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        # Driver/validation exceptions may contain URLs or submitted manifest data.
        print("Demo operation failed closed. Do not blindly retry an ambiguous apply; use verify-existing.", file=sys.stderr)
        raise SystemExit(1) from None
