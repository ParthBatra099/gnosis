"""Guarded, explicit-target demo preparation. No environment-derived connection."""
import argparse
import getpass
import json
import os
from pathlib import Path
import sys
import warnings

from run_local_demo import install_demo_configuration, demo_engine_options


class Progress:
    STAGES = frozenset({"PREPARATION", "PASSWORD_INPUT", "ENGINE_CONSTRUCTION",
        "CONNECTION_ESTABLISHMENT", "TARGET_IDENTITY_VERIFICATION", "SCHEMA_VALIDATION",
        "ALEMBIC_GRAPH_VALIDATION", "DRY_RUN_TRANSACTION_COMPLETION", "MIGRATION_EXECUTION",
        "MIGRATION_REVISION_VERIFICATION", "APPLY_TRANSACTION_COMPLETION", "DATASET_PREPARATION",
        "RECEIPT_PUBLICATION", "ENGINE_DISPOSAL"})

    def __init__(self):
        self.stage = "PREPARATION"

    def set(self, stage):
        if stage not in self.STAGES:
            raise ValueError("Unknown preparation stage")
        self.stage = stage


def failure_diagnostic(progress, error):
    """Never stringify exceptions, driver diagnostics, URLs, arguments or paths.

    Unknown exception names are redacted: custom class names can contain secrets.
    Only registered psycopg SQLSTATEs, from a real driver error or DBAPI wrapper,
    are eligible. Arbitrary exception attributes and exception chains are ignored.
    """
    names = {"Exception", "KeyboardInterrupt", "ValueError", "TypeError", "RuntimeError", "OSError", "EOFError",
        "FileNotFoundError", "PermissionError", "UnicodeEncodeError", "UnicodeDecodeError",
        "ImportError", "ModuleNotFoundError", "ValidationError", "GetPassWarning", "TimeoutError",
        "OperationalError", "InterfaceError", "ProgrammingError", "DatabaseError", "DBAPIError",
        "IntegrityError", "DataError", "InternalError", "NotSupportedError", "InvalidRequestError",
        "ArgumentError", "NoSuchModuleError", "ResourceClosedError", "PendingRollbackError",
        "CommandError", "ResolutionError", "MultipleHeads", "NoResultFound", "MultipleResultsFound",
        "InvalidPassword", "InvalidAuthorizationSpecification", "InsufficientPrivilege",
        "InvalidCatalogName", "InvalidSchemaName", "QueryCanceled", "LockNotAvailable",
        "ConnectionFailure", "ConnectionTimeout", "UndefinedTable", "UndefinedObject", "SyntaxError",
        "TargetVerificationError"}
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
                psycopg.errors.lookup(code)  # Reject unregistered/opaque attribute values.
                sqlstate = code
    except Exception:
        pass  # Diagnostics must never replace or disclose the protected failure.
    if sqlstate in {"28P01", "28000"}:
        category = "AUTHENTICATION_FAILURE"
    elif sqlstate and sqlstate.startswith("08"):
        category = "CONNECTION_FAILURE"
    elif sqlstate == "42501":
        category = "INSUFFICIENT_PRIVILEGE"
    elif sqlstate in {"57014", "55P03"}:
        category = "DATABASE_WAIT_FAILURE"
    elif sqlstate:
        category = "DATABASE_FAILURE"
    else:
        category = {"PREPARATION": "INPUT_OR_CONFIGURATION_FAILURE", "PASSWORD_INPUT": "SECURE_INPUT_FAILURE",
            "ENGINE_CONSTRUCTION": "ENGINE_SETUP_FAILURE", "CONNECTION_ESTABLISHMENT": "CONNECTION_FAILURE",
            "TARGET_IDENTITY_VERIFICATION": "TARGET_VERIFICATION_FAILURE", "SCHEMA_VALIDATION": "SCHEMA_VALIDATION_FAILURE",
            "ALEMBIC_GRAPH_VALIDATION": "MIGRATION_GRAPH_FAILURE", "DRY_RUN_TRANSACTION_COMPLETION": "TRANSACTION_COMPLETION_FAILURE",
            "APPLY_TRANSACTION_COMPLETION": "TRANSACTION_COMPLETION_FAILURE"}.get(progress.stage, "PREPARATION_FAILURE")
    stage = progress.stage if progress.stage in Progress.STAGES else "PREPARATION"
    result = dict(stage=stage, exception=name, sqlstate=sqlstate, category=category)
    # Accept metadata only from the exact internal exception type, and recheck
    # allowlists before output. Never classify by parsing exception messages.
    try:
        # Early CLI failures must not import business modules before private
        # configuration has been installed (which could load ordinary settings).
        module = sys.modules.get("app.services.demo_preparation")
        error_type = getattr(module, "TargetVerificationError", None)
        if (error_type is not None and type(error) is error_type
                and type(error.category) is str and error.category in error_type.CATEGORIES):
            result["category"] = error.category
            if (error.category == "DATABASE_IDENTITY_VALIDATION_FAILURE"
                    and type(error.field) is str and error.field in error_type.IDENTITY_FIELDS):
                result["field"] = error.field
    except Exception:
        pass
    return result


class PreparationParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default error includes supplied argument values and paths.
        raise ValueError("Invalid preparation arguments")


def parser():
    result = PreparationParser(description="Prepare a disposable LOCAL DEMO database only")
    result.add_argument("command", choices=("migrate", "load-business-data"))
    result.add_argument("--local-demo", action="store_true", required=True)
    result.add_argument("--ack-disposable-demo", action="store_true", required=True)
    result.add_argument("--target", type=Path, required=True)
    result.add_argument("--manifest", type=Path)
    result.add_argument("--operator")
    result.add_argument("--apply-confirmation")
    return result


def read_descriptor(path):
    from app.services.demo_bootstrap import DemoContract, DemoTarget
    from pydantic import Field, model_validator

    class Descriptor(DemoContract):
        target: DemoTarget
        hostaddr: str
        migration_owner_role: str = Field(pattern=r"^[A-Za-z0-9_-]{1,63}$")
        application_role: str = Field(pattern=r"^[A-Za-z0-9_-]{1,63}$")

        @model_validator(mode="after")
        def separate(self):
            validate_network(self.target.host, self.hostaddr)
            if self.migration_owner_role == self.application_role:
                raise ValueError("Separate owner and application roles required")
            if self.target.database_role != self.application_role:
                raise ValueError("Target must identify the approved application role")
            return self

    return Descriptor.model_validate_json(path.read_text(encoding="utf-8"))


def validate_network(host, hostaddr):
    if hostaddr not in ("127.0.0.1", "::1") or host not in ("localhost", hostaddr):
        raise ValueError("Explicit matching loopback hostaddr required")
    # Never display environment values. Reject inherited libpq configuration,
    # including service files and destination overrides, before engine creation.
    if any(name.upper().startswith("PG") for name in os.environ):
        raise ValueError("Ambient PostgreSQL configuration is not permitted")


def password_prompt():
    if not sys.stdin.isatty():
        raise ValueError("Protected interactive credential input required")
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        return getpass.getpass("Approved disposable database role password: ")


def main(argv=None, *, progress=None):
    progress = progress if progress is not None else Progress()
    args = parser().parse_args(argv)
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    install_demo_configuration()
    descriptor = read_descriptor(args.target)
    target = descriptor.target
    confirmation = f"APPLY:{args.command}:{target.instance_id}"
    if args.apply_confirmation not in (None, confirmation):
        raise ValueError("Exact command and demo instance confirmation required")
    from app.services.demo_bootstrap import DemoManifest
    from app.services.demo_preparation import migrate, load_business_data
    manifest = None
    if args.command == "load-business-data":
        if args.manifest is None or not args.operator:
            raise ValueError("Reviewed manifest and operator required")
        manifest = DemoManifest.model_validate_json(args.manifest.read_text(encoding="utf-8"))
    else:
        target = target.model_copy(update={"database_role": descriptor.migration_owner_role})
    from sqlalchemy import create_engine, event
    from sqlalchemy.engine import URL
    from sqlalchemy.orm import Session
    validate_network(target.host, descriptor.hostaddr)
    progress.set("PASSWORD_INPUT")
    password = password_prompt()
    progress.set("ENGINE_CONSTRUCTION")
    options = demo_engine_options()
    options["connect_args"]["hostaddr"] = descriptor.hostaddr
    engine = create_engine(URL.create("postgresql+psycopg", username=target.database_role,
        password=password, host=target.host, port=target.port, database=target.database), **options)
    del password
    try:
        @event.listens_for(engine, "do_connect")
        def guard_connection(dialect, record, cargs, cparams):
            validate_network(target.host, descriptor.hostaddr)
            if (cargs or cparams.get("hostaddr") != descriptor.hostaddr
                    or cparams.get("host") != target.host
                    or str(cparams.get("port")) != str(target.port)
                    or cparams.get("dbname") != target.database
                    or cparams.get("user") != target.database_role
                    or any(key in cparams for key in ("service", "servicefile"))):
                raise ValueError("Connection parameters do not match approved target")
        apply = args.apply_confirmation is not None
        progress.set("CONNECTION_ESTABLISHMENT")
        if args.command == "migrate":
            with engine.begin() as connection:
                migrate(connection, target, hostaddr=descriptor.hostaddr, apply=apply, stage=progress.set)
                progress.set("APPLY_TRANSACTION_COMPLETION" if apply else "DRY_RUN_TRANSACTION_COMPLETION")
            receipt = dict(status="MIGRATED_0012" if apply else "DRY_RUN", instance_id=str(target.instance_id))
        else:
            with Session(engine, autoflush=False) as db, db.begin():
                progress.set("DATASET_PREPARATION")
                receipt = load_business_data(db, manifest, target, hostaddr=descriptor.hostaddr,
                                             operator=args.operator, apply=apply)
                progress.set("APPLY_TRANSACTION_COMPLETION" if apply else "DRY_RUN_TRANSACTION_COMPLETION")
        # Print only after successful commit; never include connection URL or credentials.
        progress.set("RECEIPT_PUBLICATION")
        print(json.dumps(receipt, sort_keys=True))
    finally:
        if sys.exc_info()[0] is None:
            progress.set("ENGINE_DISPOSAL")
        engine.dispose()


def run(argv=None):
    progress = Progress()
    try:
        main(argv, progress=progress)
        return 0
    except (Exception, KeyboardInterrupt) as error:
        print(json.dumps(failure_diagnostic(progress, error), sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(run())
