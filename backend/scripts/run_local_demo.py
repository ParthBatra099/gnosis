"""Explicit loopback HTTPS launcher / dry-run-first identity bootstrap.

No app imports until explicit arguments and a private configuration are selected.
"""
import argparse
import base64
import getpass
import json
import os
from pathlib import Path
import secrets
import sys
import warnings
from types import ModuleType, SimpleNamespace


class Progress:
    STAGES = frozenset({"PREPARATION", "DATABASE_PASSWORD_INPUT", "ENGINE_CONSTRUCTION",
        "CONNECTION_ESTABLISHMENT", "TARGET_VERIFICATION", "ADVISORY_LOCK",
        "IDENTITY_INSPECTION", "USER_PASSWORD_INPUT", "PASSWORD_VALIDATION", "PASSWORD_HASHING",
        "DEPARTMENT_INSERTION", "USER_INSERTION", "AUDIT_INSERTION", "PREFLIGHT_COMPLETION",
        "APPLY_COMMIT", "RECEIPT_VERIFICATION", "VERIFY_COMPLETION", "SUCCESS_PUBLICATION",
        "DEMO_SERVE", "ENGINE_DISPOSAL"})

    def __init__(self):
        self.stage = "PREPARATION"
        self.cleanup_failures = []

    def set(self, stage):
        if type(stage) is not str or stage not in self.STAGES:
            raise ValueError("Unknown bootstrap stage")
        self.stage = stage


def failure_diagnostic(progress, error):
    """Do not stringify errors, driver diagnostics, arguments, URLs or paths."""
    names = {"Exception", "ValueError", "TypeError", "RuntimeError", "OSError", "EOFError",
        "FileNotFoundError", "PermissionError", "UnicodeEncodeError", "UnicodeDecodeError",
        "ImportError", "ModuleNotFoundError", "ValidationError", "GetPassWarning", "TimeoutError",
        "OperationalError", "InterfaceError", "ProgrammingError", "DatabaseError", "DBAPIError",
        "IntegrityError", "DataError", "InternalError", "NotSupportedError", "InvalidRequestError",
        "ArgumentError", "NoSuchModuleError", "ResourceClosedError", "PendingRollbackError",
        "NoResultFound", "MultipleResultsFound", "InvalidPassword", "InsufficientPrivilege",
        "QueryCanceled", "LockNotAvailable", "BootstrapValidationError", "KeyboardInterrupt"}
    name = type(error).__name__
    name = name if name in names else "Exception"
    sqlstate = None
    try:
        from sqlalchemy.exc import DBAPIError
        import psycopg
        candidate = error.orig if isinstance(error, DBAPIError) else error
        if isinstance(candidate, psycopg.Error):
            code = candidate.sqlstate
            if type(code) is str and len(code) == 5 and code.isascii() and code.isalnum():
                psycopg.errors.lookup(code)
                sqlstate = code
    except Exception:
        pass
    stage = progress.stage if type(progress.stage) is str and progress.stage in Progress.STAGES else "PREPARATION"
    category = {
        "PREPARATION": "INPUT_OR_CONFIGURATION_FAILURE", "DATABASE_PASSWORD_INPUT": "SECURE_INPUT_FAILURE",
        "USER_PASSWORD_INPUT": "SECURE_INPUT_FAILURE", "ENGINE_CONSTRUCTION": "ENGINE_SETUP_FAILURE",
        "CONNECTION_ESTABLISHMENT": "CONNECTION_FAILURE", "TARGET_VERIFICATION": "TARGET_VERIFICATION_FAILURE",
        "ADVISORY_LOCK": "DATABASE_LOCK_FAILURE", "IDENTITY_INSPECTION": "IDENTITY_VALIDATION_FAILURE",
        "PASSWORD_VALIDATION": "PASSWORD_POLICY_FAILURE", "PASSWORD_HASHING": "PASSWORD_HASHING_FAILURE",
        "DEPARTMENT_INSERTION": "DEPARTMENT_INSERTION_FAILURE", "USER_INSERTION": "USER_INSERTION_FAILURE",
        "AUDIT_INSERTION": "AUDIT_INSERTION_FAILURE", "PREFLIGHT_COMPLETION": "TRANSACTION_COMPLETION_FAILURE",
        "APPLY_COMMIT": "TRANSACTION_COMPLETION_FAILURE", "RECEIPT_VERIFICATION": "BOOTSTRAP_VERIFICATION_FAILURE",
        "VERIFY_COMPLETION": "TRANSACTION_COMPLETION_FAILURE", "SUCCESS_PUBLICATION": "OUTPUT_FAILURE",
        "DEMO_SERVE": "DEMO_STARTUP_FAILURE", "ENGINE_DISPOSAL": "CLEANUP_FAILURE",
    }[stage]
    if sqlstate in {"28P01", "28000"}:
        category = "AUTHENTICATION_FAILURE"
    elif sqlstate == "42501":
        category = "INSUFFICIENT_PRIVILEGE"
    elif sqlstate in {"57014", "55P03"}:
        category = "DATABASE_WAIT_FAILURE"
    elif sqlstate and sqlstate.startswith("08"):
        category = "CONNECTION_FAILURE"
    elif sqlstate:
        category = "DATABASE_FAILURE"
    module = sys.modules.get("app.services.demo_bootstrap")
    error_type = getattr(module, "BootstrapValidationError", None)
    if error_type is not None and type(error) is error_type:
        if type(error.category) is str and error.category in error_type.CATEGORIES:
            category = error.category
    return dict(stage=stage, exception=name, sqlstate=sqlstate, category=category)


class DemoParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse normally echoes user-provided argument values.
        raise ValueError("Invalid demo arguments")


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


def validate_bootstrap_network(target):
    if target.host != "127.0.0.1" or any(name.upper().startswith("PG") for name in os.environ):
        raise ValueError("Explicit IPv4 loopback and no ambient PostgreSQL configuration required")


def guard_demo_connection(target, cargs, cparams):
    # Recheck immediately before every DBAPI connection, including pool reconnects.
    validate_bootstrap_network(target)
    if (cargs or cparams.get("host") != "127.0.0.1" or cparams.get("hostaddr") != "127.0.0.1"
            or str(cparams.get("port")) != str(target.port)
            or cparams.get("dbname") != target.database or cparams.get("user") != target.database_role
            or any(key in cparams for key in ("service", "servicefile"))):
        raise ValueError("Connection parameters do not match approved target")


def password_prompt(prompt):
    if not sys.stdin.isatty():
        raise ValueError("Interactive terminal required")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            return getpass.getpass(prompt)
    except (getpass.GetPassWarning, EOFError, OSError):
        raise ValueError("Protected password input unavailable") from None


def parser():
    result = DemoParser(description="GNOSIS LOCAL DEMO — password-only, fictional identities")
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


def main(argv=None, *, progress=None):
    progress = progress if progress is not None else Progress()
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
    validate_bootstrap_network(target)
    from sqlalchemy import create_engine, event, text
    from sqlalchemy.engine import URL
    from sqlalchemy.orm import Session
    # The explicitly supplied target, never DATABASE_URL, chooses the connection.
    progress.set("DATABASE_PASSWORD_INPUT")
    password = password_prompt("Disposable demo PostgreSQL role password: ")
    progress.set("ENGINE_CONSTRUCTION")
    url = URL.create("postgresql+psycopg", username=target.database_role, password=password,
                     host=target.host, port=target.port, database=target.database)
    options = demo_engine_options()
    options["connect_args"]["hostaddr"] = "127.0.0.1"
    bind = create_engine(url, **options)
    del password
    try:
        @event.listens_for(bind, "do_connect")
        def guard_connection(dialect, record, cargs, cparams):
            guard_demo_connection(target, cargs, cparams)

        with Session(bind, autoflush=False) as db, db.begin():
            progress.set("CONNECTION_ESTABLISHMENT")
            db.connection()
            progress.set("TARGET_VERIFICATION")
            verify_target(db, target)
            if args.command == "bootstrap":
                # Cooperating launchers serialize without adding schema objects.
                progress.set("ADVISORY_LOCK")
                db.execute(text("SELECT pg_advisory_xact_lock(1196314447)"))
                bootstrap(db, manifest, target, operator=args.operator, stage=progress.set)
                progress.set("PREFLIGHT_COMPLETION")
            else:
                progress.set("RECEIPT_VERIFICATION")
                verify_existing(db, manifest, target)
                progress.set("VERIFY_COMPLETION")
        if args.apply_confirmation:
            # Never hold a connection/transaction during interactive prompts.
            passwords = {}
            try:
                for user in manifest.users:
                    progress.set("USER_PASSWORD_INPUT")
                    first = password_prompt(f"Password for fictional {user.email}: ")
                    if first != password_prompt("Repeat password: "):
                        raise ValueError("Password confirmation mismatch")
                    passwords[str(user.id)] = first
                with Session(bind, autoflush=False) as db, db.begin():
                    progress.set("CONNECTION_ESTABLISHMENT")
                    db.connection()
                    progress.set("TARGET_VERIFICATION")
                    verify_target(db, target)
                    progress.set("ADVISORY_LOCK")
                    db.execute(text("SELECT pg_advisory_xact_lock(1196314447)"))
                    bootstrap(db, manifest, target, operator=args.operator, passwords=passwords, stage=progress.set)
                    progress.set("APPLY_COMMIT")
            finally:
                passwords.clear()
        if args.command != "serve":
            progress.set("SUCCESS_PUBLICATION")
            print("Demo bootstrap APPLIED" if args.apply_confirmation else "Demo validation PASSED (no identity writes)")
            return 0
        progress.set("DEMO_SERVE")
        from app.demo_app import create_demo_app
        import uvicorn
        app = create_demo_app(local_demo=True, acknowledge_password_only=True, bind=bind,
                              manifest=manifest, target=target, origins=args.origin)
        print("DEMO MODE — Password-only authentication for fictional local accounts. MFA is not being demonstrated.")
        uvicorn.run(app, host="127.0.0.1", port=args.port, workers=1, reload=False,
                    proxy_headers=False, ssl_certfile=str(args.tls_cert), ssl_keyfile=str(args.tls_key),
                    access_log=False)
    finally:
        primary_failure = sys.exc_info()[0] is not None
        if primary_failure:
            try:
                bind.dispose()
            except (Exception, KeyboardInterrupt) as cleanup_error:
                cleanup_progress = Progress()
                cleanup_progress.set("ENGINE_DISPOSAL")
                progress.cleanup_failures.append(failure_diagnostic(cleanup_progress, cleanup_error))
        else:
            progress.set("ENGINE_DISPOSAL")
            bind.dispose()
    return 0


def run(argv=None):
    progress = Progress()
    try:
        return main(argv, progress=progress)
    except (Exception, KeyboardInterrupt) as error:
        print(json.dumps(failure_diagnostic(progress, error), sort_keys=True), file=sys.stderr)
        for cleanup in progress.cleanup_failures:
            print(json.dumps(cleanup, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(run())
