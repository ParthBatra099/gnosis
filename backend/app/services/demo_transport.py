"""Demo-local Secure/HttpOnly/Strict cookies and session-bound signed CSRF.

Independent keys/cookie namespace; ignores forwarded headers and bearer tokens.
"""
import base64
import hashlib
import hmac
import ipaddress
import json
import secrets
from urllib.parse import urlsplit

from fastapi import HTTPException
from app.services.authentication_common import clock, fingerprint

SESSION_COOKIE = "__Host-gnosis_demo_session"
CSRF_COOKIE = "__Host-gnosis_demo_csrf"


class DemoTransport:
    def __init__(self, registry, origins):
        if not origins:
            raise ValueError("Explicit loopback HTTPS origins required")
        for value in origins:
            origin = urlsplit(value)
            if (origin.scheme != "https" or origin.hostname not in {"localhost", "127.0.0.1", "::1"}
                    or origin.username or origin.password or origin.path or origin.query or origin.fragment
                    or value != f"https://{origin.netloc}"):
                raise ValueError("Only exact loopback HTTPS origins permitted")
            origin.port
        self.registry, self.origins = registry, tuple(origins)

    def secure(self, request):
        try:
            local = ipaddress.ip_address(request.client.host).is_loopback
        except (ValueError, AttributeError):
            local = False
        if (not local or request.url.scheme != "https"
                or request.url.hostname not in {"localhost", "127.0.0.1", "::1"}
                or any(h in request.headers for h in ("forwarded", "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host"))):
            raise HTTPException(403, "Local demo transport rejected")

    def origin(self, request):
        self.secure(request)
        value = request.headers.get("origin")
        if value not in self.origins:
            raise HTTPException(403, "Demo origin rejected")
        return value

    def csrf(self, request, sid=None):
        origin = self.origin(request)
        sid = sid or request.cookies.get(SESSION_COOKIE)
        payload = [origin, int(clock().timestamp()), secrets.token_urlsafe(32), fingerprint(sid) if sid else "anonymous"]
        encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()
        return encoded + "." + hmac.new(self.registry.csrf_key, encoded.encode(), hashlib.sha256).hexdigest()

    def verify(self, request):
        origin = self.origin(request)
        value = request.headers.get("x-csrf-token", "")
        try:
            cookie = request.cookies.get(CSRF_COOKIE, "")
            if (not value or len(value) > 2048 or len(cookie) > 2048
                    or not value.isascii() or not cookie.isascii()
                    or not hmac.compare_digest(value.encode("ascii"), cookie.encode("ascii"))):
                raise ValueError()
            encoded, signature = value.split(".")
            expected = hmac.new(self.registry.csrf_key, encoded.encode(), hashlib.sha256).hexdigest()
            payload = json.loads(base64.b64decode(encoded, altchars=b"-_", validate=True))
            sid = request.cookies.get(SESSION_COOKIE)
            if (not hmac.compare_digest(expected, signature) or not isinstance(payload, list) or len(payload) != 4
                    or payload[0] != origin or type(payload[1]) is not int
                    or not 0 <= clock().timestamp() - payload[1] < 600
                    or payload[3] != (fingerprint(sid) if sid else "anonymous")):
                raise ValueError()
        except (ValueError, TypeError, IndexError):
            raise HTTPException(403, "CSRF validation failed") from None

    @staticmethod
    def cookie(response, name, value, seconds):
        response.set_cookie(name, value, max_age=seconds, secure=True, httponly=True, samesite="strict", path="/")
        response.headers["Cache-Control"] = "no-store"
