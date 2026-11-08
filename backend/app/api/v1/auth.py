from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, Request, Query, Path
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.routing import APIRoute
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.config import settings
from app.core.database import get_db
from app.core.security import create_access_token
from app.models import User
from app.schemas.auth import LoginRequest, ChallengeRequest, VerificationRequest, SessionPage, SessionRevokeRequest
from app.services import session_management
from app.schemas.user import UserRead
from app.services import mfa_workflows as workflows
from app.services.authentication_challenges import ChallengeTicket
from app.services.authentication_common import AuthenticationError, clock
from app.services.authentication_rate_limits import RateLimitUnavailable
from app.services.authentication_sessions import invalidate_user_sessions, revoke_session
from app.services.authentication_transport import CSRF_COOKIE, SESSION_COOKIE, clear_cookies, issue_csrf, set_cookie, source_identifier, verify_csrf, require_signing_configuration


class AuthenticationRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()
        async def safe_handler(request):
            try:
                response = await handler(request)
            except RequestValidationError:
                response = JSONResponse({"detail": "Authentication failed"}, status_code=401)
            response.headers["Cache-Control"] = "no-store"
            return response
        return safe_handler


router = APIRouter(route_class=AuthenticationRoute)


def _ticket(payload):
    return ChallengeTicket(payload.challenge_id, payload.challenge_secret.get_secret_value())


def _run(request, db, stage, operation, *, account=None, challenge_id=None):
    verify_csrf(request)
    require_signing_configuration()
    source = source_identifier(request)
    try:
        # Protective counters commit before verification; denials cannot undo them.
        with Session(bind=db.get_bind(), autoflush=False) as tx, tx.begin():
            allowed = workflows.throttle(tx, source=source, stage=stage, account=account, challenge_id=challenge_id)
        if not allowed:
            raise HTTPException(429, "Authentication failed")
        with Session(bind=db.get_bind(), autoflush=False) as tx, tx.begin():
            result = operation(tx)
    except RateLimitUnavailable:
        raise HTTPException(503, "Authentication unavailable") from None
    except AuthenticationError:
        try:
            with Session(bind=db.get_bind(), autoflush=False) as tx, tx.begin():
                workflows.failure(tx, stage=stage)
        except Exception:
            raise HTTPException(503, "Authentication unavailable") from None
        raise HTTPException(401, "Authentication failed") from None
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(503, "Authentication unavailable") from None
    if not result.allowed:
        raise HTTPException(401, "Authentication failed")
    payload = result.payload
    if result.principal:
        principal = result.principal
        csrf = issue_csrf(request, session_id=principal.authentication_context_id)
        response = JSONResponse({**payload, "csrf_token": csrf})
        lifetime = min(settings.AUTH_SESSION_ABSOLUTE_SECONDS, max(1, int((principal.expires_at - clock()).total_seconds())))
        token = create_access_token(principal.subject_user_id, timedelta(seconds=lifetime), session_id=principal.authentication_context_id)
        set_cookie(response, SESSION_COOKIE, token, lifetime)
        set_cookie(response, CSRF_COOKIE, csrf, settings.AUTH_CSRF_LIFETIME_SECONDS)
        return response
    return JSONResponse(payload, headers={"Cache-Control": "no-store"})


@router.get("/csrf")
def csrf_bootstrap(request: Request):
    csrf = issue_csrf(request)
    response = JSONResponse({"csrf_token": csrf})
    set_cookie(response, CSRF_COOKIE, csrf, settings.AUTH_CSRF_LIFETIME_SECONDS)
    return response


@router.post("/login")
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    return _run(request, db, "password", lambda tx: workflows.password_login(
        tx, str(payload.email), payload.password.get_secret_value(), recover=payload.intent == "recover"), account=str(payload.email))


@router.post("/mfa/enroll")
def enroll(payload: ChallengeRequest, request: Request, db: Session = Depends(get_db)):
    return _run(request, db, "enroll", lambda tx: workflows.start_enrollment(
        tx, _ticket(payload), authorizer=getattr(request.app.state, "enrollment_authorizer", None)), challenge_id=payload.challenge_id)


@router.post("/mfa/enroll/verify")
def verify_enrollment(payload: VerificationRequest, request: Request, db: Session = Depends(get_db)):
    return _run(request, db, "enroll", lambda tx: workflows.confirm_enrollment(
        tx, _ticket(payload), payload.code.get_secret_value(),
        authorizer=getattr(request.app.state, "enrollment_authorizer", None)), challenge_id=payload.challenge_id)


@router.post("/mfa/verify")
def verify_mfa(payload: VerificationRequest, request: Request, db: Session = Depends(get_db)):
    return _run(request, db, "totp", lambda tx: workflows.verify_mfa(
        tx, _ticket(payload), payload.code.get_secret_value()), challenge_id=payload.challenge_id)


@router.post("/recovery/verify")
def recover(payload: VerificationRequest, request: Request, db: Session = Depends(get_db)):
    return _run(request, db, "recovery", lambda tx: workflows.recover_account(
        tx, _ticket(payload), payload.code.get_secret_value()), challenge_id=payload.challenge_id)


@router.get("/me", response_model=UserRead)
def get_current_user_profile(current_user: User = Depends(get_current_user)):
    return current_user


def _logout(request, db, user, *, everywhere):
    principal = request.state.principal
    try:
        with Session(bind=db.get_bind(), autoflush=False) as tx, tx.begin():
            if everywhere:
                invalidate_user_sessions(tx, user.id, actor_user_id=user.id, reason="USER_REQUEST", now=clock())
            else:
                revoke_session(tx, principal.authentication_context_id, actor_user_id=user.id, now=clock())
    except Exception:
        raise HTTPException(503, "Authentication unavailable") from None
    response = Response(status_code=204)
    clear_cookies(response)
    return response


@router.post("/logout", status_code=204)
def logout(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return _logout(request, db, current_user, everywhere=False)


@router.post("/logout-all", status_code=204)
def logout_all(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return _logout(request, db, current_user, everywhere=True)


@router.get("/sessions", response_model=SessionPage)
def own_sessions(request: Request, limit: int = Query(default=20, ge=1, le=100),
                 offset: int = Query(default=0, ge=0, le=100000),
                 current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        return session_management.inventory(db, current_user.id, current_user.id,
                                            request.state.principal.authentication_context_id, limit=limit, offset=offset)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(503, "Authentication unavailable") from None


@router.post("/sessions/{session_ref}/revoke", status_code=204)
def revoke_own_session(payload: SessionRevokeRequest, request: Request, session_ref: str = Path(pattern=r"^[0-9a-f]{64}$"),
                       current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        session_management.revoke(db, current_user.id, current_user.id, session_ref, payload.reason,
                                  request.state.principal.authentication_context_id)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(503, "Authentication unavailable") from None
    return Response(status_code=204)
