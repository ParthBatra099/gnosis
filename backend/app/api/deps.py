from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.security import decode_access_token
from app.models.user import User
from app.services.authentication_common import AuthenticationError, clock
from app.services.authentication_sessions import validate_session
from app.services.authentication_transport import SESSION_COOKIE, SAFE_METHODS, require_secure, require_signing_configuration, verify_csrf

security_bearer = HTTPBearer(auto_error=False)


def get_current_user(request: Request,
                     credentials: HTTPAuthorizationCredentials | None = Depends(security_bearer),
                     db: Session = Depends(get_db)) -> User:
    """Only persisted MFA sessions authenticate; claims alone never establish access."""
    require_secure(request)
    require_signing_configuration()
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        if request.method not in SAFE_METHODS:
            verify_csrf(request)
        elif request.headers.get("origin") and request.headers["origin"] not in settings.AUTH_ALLOWED_ORIGINS:
            raise HTTPException(403, "Authentication origin rejected")
    elif (settings.AUTH_ALLOW_BEARER_SESSIONS and credentials is not None
          and not request.headers.get("origin")):
        token = credentials.credentials
    else:
        raise HTTPException(401, "Not authenticated")
    try:
        claims = decode_access_token(token)
        user_id, session_id = claims.get("sub"), claims.get("sid")
        if not isinstance(user_id, str) or not isinstance(session_id, str):
            raise AuthenticationError("Persisted session required")
        with Session(bind=db.get_bind(), autoflush=False) as auth_db, auth_db.begin():
            principal = validate_session(auth_db, user_id, session_id, touch=True, now=clock())
        user = db.query(User).filter_by(id=user_id).populate_existing().first()
        if user is None or not user.active:
            raise AuthenticationError("Unavailable identity")
    except (jwt.PyJWTError, AuthenticationError, LookupError):
        raise HTTPException(401, "Not authenticated") from None
    except Exception:
        raise HTTPException(503, "Authentication unavailable") from None
    request.state.principal = principal
    return user
