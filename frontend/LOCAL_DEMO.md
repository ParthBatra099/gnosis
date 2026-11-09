# Local evaluation frontend

The normal `index.html` / `src/main.tsx` entry and normal login controller still use
mandatory MFA. No environment variable activates the demo in that entry. Demo is
explicitly selected through `demo.html` / `src/demo/main.tsx`; there is no MFA fallback.
The normal production build excludes the demo entry. The demo build is separate.

Prerequisites: separately prepared fictional demo identities and an explicitly launched
demo backend, plus locally trusted HTTPS certificates. This change does not provision
accounts, start backend services or migrate databases. It is local evaluation only.

From `frontend`, using existing dependencies:

```powershell
$env:VITE_DEMO_API_BASE_URL = 'https://localhost:8443'
$env:GNOSIS_DEMO_TLS_CERT = '<existing-certificate-path>'
$env:GNOSIS_DEMO_TLS_KEY = '<existing-private-key-path>'
npm run dev:demo
# Or: npm run build:demo, then npm run preview:demo
```

Open `https://localhost:5173/demo.html#/login`. The frontend and API must use the same
hostname (for example localhost on both) so SameSite=Strict cookies work across ports.
The backend's explicit `--origin` must be `https://localhost:5173`. The demo Vite server
binds 127.0.0.1 only and refuses startup without explicit certificate/key paths. Do not
use a reverse proxy: the backend rejects forwarded headers. Do not publish this demo.
Use a separate browser profile for normal and demo evaluation.

The demo entry rejects HTTP, public hosts and non-loopback/non-HTTPS API URLs. The banner
remains visible during startup, login, errors, dashboard navigation and session expiry:

**DEMO MODE — Password-only authentication for fictional local accounts. MFA is not being demonstrated.**

## HTTP contract

- `GET /health`: fresh mode agreement before profile restoration/refresh; requires
  `auth_mode: LOCAL_DEMO_PASSWORD_ONLY` and `demo_mode:true`. Wrong backend mode fails
  closed before `/auth/me`. This avoids rotating CSRF cookies during background refresh.
- `GET /auth/csrf`: credentials included; exact HTTPS Origin; response must include
  the exact demo `auth_mode` and `csrf_token`. Used before login/logout and when an unsafe
  request needs a new CSRF header token.
- `POST /auth/login`: `{email,password,intent:"login"}`, with credentials and signed
  `X-CSRF-Token`. Accept only `authenticated:true`, the exact demo auth mode and a new
  CSRF token. An MFA challenge is never accepted as a demo login.
- `GET /auth/me`: persisted user profile, including nullable canonical organization_role.
  Never infer identity from legacy role. No role-specific navigation for unknown roles.
- `POST /auth/logout`: credentials and session-bound CSRF, with no secret request body.
  Local identity clears immediately; failed server revocation is reported, not called success.
- Existing own-session and Super Admin cross-user session URLs are reused unchanged.

The browser manages `__Host-gnosis_demo_session` and `__Host-gnosis_demo_csrf` cookies
(Secure, HttpOnly, Strict, Path=/). JavaScript does not read them or retain session IDs.
Only the returned CSRF header value lives in memory. No passwords/tokens are written
to localStorage or sessionStorage. Login clears the password input after submission.
Protected 401 and demo 503 clear frontend identity/data through existing rejection
listeners. No failed mutation is automatically replayed. Focus/visibility changes
revalidate profiles; logout/rejection supersedes late async responses.

Shared layouts, canonical-role navigation, employee pages, monitoring, incidents,
organization management and session pages retain existing backend permissions. Role
presentation grants no department scope or data permission. Existing backend lifecycle
restrictions still apply: creating an ordinary employee does not qualify it for demo
login, and reactivation may require real MFA setup. No fake data or metrics were added.

Live PostgreSQL, browser TLS/cookie behavior and end-to-end frontend/backend integration
remain unverified until an explicit environment is available. Node tests mock HTTP and
render components; they do not prove browser transport behavior.
