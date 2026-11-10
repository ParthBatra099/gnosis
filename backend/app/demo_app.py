"""Explicit local evaluation factory. Normal app.main never imports this module."""
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Path, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from fastapi.exceptions import RequestValidationError
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models import AuditEvent, User
from app.schemas.auth import LoginRequest, SessionPage, SessionRevokeRequest
from app.schemas.user import UserRead
from app.services import demo_bootstrap as bootstrap
from app.services import organization_management as organization
from app.services.authentication_common import AuthenticationError, fingerprint
from app.services.authentication_rate_limits import RateLimitCategory, RateLimitPolicy, record_attempt
from app.services.demo_authentication import DemoSessions, MODE
from app.services.demo_transport import DemoTransport, SESSION_COOKIE, CSRF_COOKIE


def create_demo_app(*, local_demo=False, acknowledge_password_only=False, bind, manifest, target, origins):
    if local_demo is not True or acknowledge_password_only is not True:
        raise ValueError("Explicit local demo activation and password-only acknowledgement required")
    # Factory cannot self-bless a target: validate the external marker and receipt.
    with Session(bind) as db, db.begin():
        bootstrap.verify_target(db, target)
        bootstrap.validate_receipt(db, manifest, target)
    registry = DemoSessions(manifest, target)
    transport = DemoTransport(registry, origins)
    app = FastAPI(title="GNOSIS — DEMO MODE", debug=False)
    app.state.demo_sessions = registry
    app.state.auth_mode = MODE
    app.add_middleware(CORSMiddleware, allow_origins=list(origins), allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "X-CSRF-Token"])

    @app.exception_handler(RequestValidationError)
    async def private_validation(request, exc):
        # Never echo passwords or other submitted authentication material.
        return JSONResponse({"detail": "Invalid demo request"}, status_code=422)

    @app.middleware("http")
    async def local_only(request, call_next):
        try:
            transport.secure(request)
            registry.ensure_live()
        except HTTPException as exc:
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
        except AuthenticationError:
            return JSONResponse({"detail": "Demo run invalidated; restart required"}, status_code=503)
        response = await call_next(request)
        response.headers["X-GNOSIS-Auth-Mode"] = MODE
        response.headers["Cache-Control"] = "no-store"
        return response

    def database():
        with Session(bind, autoflush=False) as db:
            yield db

    def authenticated(request: Request, db: Session = Depends(get_db)):
        transport.secure(request)
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            transport.verify(request)
        elif request.headers.get("origin"):
            transport.origin(request)
        try:
            sid = request.cookies.get(SESSION_COOKIE)
            with registry.operation(bind, registry.user_for(sid)) as tx:
                principal = registry.validate(tx, request.cookies.get(SESSION_COOKIE), touch=True)
                user_id = principal.subject_user_id
            request.state.principal = principal
            return db.get(User, user_id, populate_existing=True)
        except AuthenticationError:
            raise HTTPException(401, "Not authenticated") from None
        except Exception:
            raise HTTPException(503, "Demo authentication unavailable") from None

    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_current_user] = authenticated
    auth = APIRouter()

    @auth.get("/csrf")
    def csrf(request: Request):
        try:
            with registry.operation(bind):
                pass
        except AuthenticationError:
            raise HTTPException(503, "Demo target unavailable; restart required") from None
        value = transport.csrf(request)
        response = JSONResponse({"csrf_token": value, "auth_mode": MODE})
        transport.cookie(response, CSRF_COOKIE, value, 600)
        return response

    @auth.post("/login")
    def login(payload: LoginRequest, request: Request):
        transport.verify(request)
        if payload.intent != "login":
            raise HTTPException(401, "Demo authentication failed")
        try:
            # Both counters commit even when one denies. Keys are private per run.
            with registry.operation(bind) as tx:
                account = record_attempt(tx, RateLimitCategory.PASSWORD_ACCOUNT, str(payload.email),
                    key=registry.rate_key, policy=RateLimitPolicy(5, 300))
                source = record_attempt(tx, RateLimitCategory.PASSWORD_SOURCE, request.client.host,
                    key=registry.rate_key, policy=RateLimitPolicy(60, 300))
            if not account.allowed or not source.allowed:
                raise HTTPException(429, "Demo authentication failed")
            user_id = next((str(u.id) for u in manifest.users if u.email == str(payload.email)), "")
            with registry.operation(bind, user_id) as tx:
                principal = registry.prepare_login(tx, str(payload.email), payload.password.get_secret_value())
            value = transport.csrf(request, principal.authentication_context_id)
            response = JSONResponse({"authenticated": True, "auth_mode": MODE, "csrf_token": value})
            transport.cookie(response, SESSION_COOKIE, principal.authentication_context_id, registry.absolute_seconds)
            transport.cookie(response, CSRF_COOKIE, value, 600)
            return response
        except HTTPException:
            raise
        except AuthenticationError:
            try:
                with registry.operation(bind) as tx:
                    tx.add(AuditEvent(actor_id=None, action="DEMO_LOGIN_FAILED", outcome="DENY",
                        reason="DEMO_AUTHENTICATION_FAILED", context_data={"auth_mode": MODE,
                        "run_id": registry.run_id}))
                    tx.flush()
            except Exception:
                raise HTTPException(503, "Demo authentication unavailable") from None
            raise HTTPException(401, "Demo authentication failed") from None
        except Exception:
            raise HTTPException(503, "Demo authentication unavailable") from None

    @auth.get("/me", response_model=UserRead)
    def me(user: User = Depends(get_current_user)):
        return user

    def revoke(request, db, actor, target_id, reason, session_ref=None):
        try:
            with registry.operation(bind, actor.id, target_id) as tx:
                registry.prepare_revocation(tx, actor.id, target_id,
                    request.state.principal.authentication_context_id, session_ref=session_ref, reason=reason)
        except (HTTPException, AuthenticationError) as exc:
            if isinstance(exc, HTTPException):
                raise
            raise HTTPException(401, "Not authenticated") from None
        except Exception:
            raise HTTPException(503, "Demo authentication unavailable") from None
        return Response(status_code=204)

    @auth.post("/logout", status_code=204)
    def logout(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
        response = revoke(request, db, user, user.id, "USER_LOGOUT",
            fingerprint(request.state.principal.authentication_context_id))
        for name in (SESSION_COOKIE, CSRF_COOKIE):
            response.delete_cookie(name, path="/", secure=True, httponly=True, samesite="strict")
        return response

    @auth.post("/logout-all", status_code=204)
    def logout_all(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
        return revoke(request, db, user, user.id, "USER_LOGOUT_ALL")

    def inventory(request, user, target_id, limit, offset):
        try:
            with registry.operation(bind, user.id, target_id) as tx:
                registry.validate(tx, request.state.principal.authentication_context_id)
                return registry.inventory(tx, user.id, target_id, request.state.principal.authentication_context_id,
                                          limit=limit, offset=offset)
        except AuthenticationError:
            raise HTTPException(401, "Not authenticated") from None

    @auth.get("/sessions", response_model=SessionPage)
    def sessions(request: Request, limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0, le=100000),
                 user: User = Depends(get_current_user)):
        return inventory(request, user, user.id, limit, offset)

    @auth.post("/sessions/{session_ref}/revoke", status_code=204)
    def revoke_own(payload: SessionRevokeRequest, request: Request, session_ref: str = Path(pattern=r"^[0-9a-f]{64}$"),
                   user: User = Depends(get_current_user), db: Session = Depends(get_db)):
        return revoke(request, db, user, user.id, payload.reason, session_ref)

    app.include_router(auth, prefix="/auth")
    from app.api.v1 import resources, access, monitoring, console, assistant
    from app.api.v1.organization import router as organization_router
    for prefix, module in (("resources", resources), ("access", access), ("monitoring", monitoring),
                           ("console", console), ("assistant", assistant)):
        app.include_router(module.router, prefix="/" + prefix)
    # Copy only non-session routes. Never mutate a shared router or normal app.
    ordinary = APIRouter()
    ordinary.routes.extend(route for route in organization_router.routes if "/sessions" not in route.path)
    app.include_router(ordinary, prefix="/organization")

    @app.get("/organization/employees/{user_id}/sessions", response_model=SessionPage)
    def employee_sessions(user_id: str, request: Request, limit: int = Query(20, ge=1, le=100),
                          offset: int = Query(0, ge=0, le=100000), user: User = Depends(get_current_user), db: Session = Depends(get_db)):
        organization.require(organization.authority.evaluate_authority(db, user.id,
            organization.A.IDENTITY_ADMINISTER, organization.authority.OrganizationScope()))
        return inventory(request, user, user_id, limit, offset)

    @app.post("/organization/employees/{user_id}/sessions/{session_ref}/revoke", status_code=204)
    def employee_revoke(user_id: str, payload: SessionRevokeRequest, request: Request,
                        session_ref: str = Path(pattern=r"^[0-9a-f]{64}$"),
                        user: User = Depends(get_current_user), db: Session = Depends(get_db)):
        # Preserve administrative-route authority even when self-targeting.
        organization.require(organization.authority.evaluate_authority(db, user.id,
            organization.A.IDENTITY_ADMINISTER, organization.authority.OrganizationScope()))
        return revoke(request, db, user, user_id, payload.reason, session_ref)

    @app.get("/health")
    def health():
        return {"status": "ok", "auth_mode": MODE, "demo_mode": True}

    return app
