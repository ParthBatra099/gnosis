"""Browser cookie/CSRF and explicit proxy boundary. No deployment origins assumed."""
import base64
import hashlib
import hmac
import ipaddress
import json
import secrets

from fastapi import HTTPException

from app.core.config import settings
from app.core.security import decode_access_token
from app.services.authentication_common import clock, fingerprint
from app.services.mfa_encryption import decode_managed_key

SESSION_COOKIE = "__Host-gnosis_session"
CSRF_COOKIE = "__Host-gnosis_csrf"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def require_signing_configuration():
    if (settings.JWT_ALGORITHM != "HS256" or len(settings.JWT_SECRET_KEY.encode()) < 32
            or settings.JWT_SECRET_KEY.startswith("CHANGEME")):
        raise HTTPException(503, "Authentication unavailable")


def _peer(request):
    try:
        return ipaddress.ip_address(request.client.host)
    except (ValueError, AttributeError):
        raise HTTPException(403, "Authentication transport rejected") from None


def _trusted(peer):
    return any(peer in ipaddress.ip_network(cidr) for cidr in settings.AUTH_TRUSTED_PROXY_CIDRS)


def secure_request(request):
    if request.url.scheme == "https":
        return True
    return bool(settings.AUTH_TRUSTED_PROXY_CIDRS and _trusted(_peer(request))
                and request.headers.get("x-forwarded-proto") == "https")


def require_secure(request):
    if not secure_request(request):
        raise HTTPException(403, "Authentication transport rejected")


def source_identifier(request):
    peer = _peer(request)
    if not _trusted(peer):
        return str(peer)  # Every forwarded header from an untrusted peer is ignored.
    try:
        forwarded = request.headers.get("x-forwarded-for", "").split(",")
        if not 1 <= len(forwarded) <= 8:
            raise ValueError
        chain = [ipaddress.ip_address(value.strip()) for value in forwarded]
    except ValueError:
        raise HTTPException(403, "Authentication transport rejected") from None
    for candidate in reversed(chain):
        if not _trusted(candidate):
            return str(candidate)
    return str(chain[0])


def require_origin(request):
    require_secure(request)
    origin = request.headers.get("origin")
    if origin is None or origin not in settings.AUTH_ALLOWED_ORIGINS:
        raise HTTPException(403, "Authentication origin rejected")
    return origin


def _csrf_key():
    if settings.AUTH_CSRF_KEY is None:
        raise HTTPException(503, "Authentication unavailable")
    try:
        return decode_managed_key(settings.AUTH_CSRF_KEY.get_secret_value())
    except ValueError:
        raise HTTPException(503, "Authentication unavailable") from None


def _binding(request):
    cookie = request.cookies.get(SESSION_COOKIE)
    if cookie:
        try:
            sid = decode_access_token(cookie).get("sid")
            if isinstance(sid, str) and 43 <= len(sid) <= 64:
                return fingerprint(sid)
        except Exception:
            pass  # An invalid cookie gets anonymous CSRF binding, never access.
    return "anonymous"


def issue_csrf(request, *, session_id=None):
    origin = require_origin(request)
    payload = json.dumps([origin, int(clock().timestamp()), secrets.token_urlsafe(32),
                          fingerprint(session_id) if session_id else _binding(request)], separators=(",", ":")).encode()
    encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    return encoded + "." + hmac.new(_csrf_key(), encoded.encode(), hashlib.sha256).hexdigest()


def verify_csrf(request):
    origin = require_origin(request)
    cookie, submitted = request.cookies.get(CSRF_COOKIE), request.headers.get("x-csrf-token")
    if not cookie or not submitted or len(submitted) > 2048 or not hmac.compare_digest(cookie, submitted):
        raise HTTPException(403, "CSRF validation failed")
    try:
        encoded, signature = submitted.split(".")
        expected = hmac.new(_csrf_key(), encoded.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError
        payload = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        if (not isinstance(payload, list) or len(payload) != 4 or payload[0] != origin
                or type(payload[1]) is not int or not 0 <= clock().timestamp() - payload[1] < settings.AUTH_CSRF_LIFETIME_SECONDS
                or payload[3] != _binding(request)):
            raise ValueError
    except (ValueError, TypeError, IndexError):
        raise HTTPException(403, "CSRF validation failed") from None


def set_cookie(response, name, value, max_age):
    response.set_cookie(name, value, max_age=max_age, secure=True, httponly=True, samesite="strict", path="/")
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


def clear_cookies(response):
    for name in (SESSION_COOKIE, CSRF_COOKIE):
        response.delete_cookie(name, path="/", secure=True, httponly=True, samesite="strict")
    response.headers["Cache-Control"] = "no-store"
