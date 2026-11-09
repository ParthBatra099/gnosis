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

## Employee business-record workflow

Open `demo.html#/employee/resources` after demo login (normal application:
`/employee/resources`). All canonical roles may use the employee resource page;
this does not grant business-data permissions. Existing admin links also lead to
this shared page. It loads only `/access/resources/metadata` on mount.

Select a resource and page size, then explicitly click **Request records**. This
calls `GET /resources/{id}/records?limit=25&offset=0` with browser cookies. GETs do not
require a CSRF header. Resource listing, selection and page size changes do not
establish permission or fetch records. Pagination and repeated requests are explicit
actions that may create new server-side disclosure evidence; there is no automatic
retry, prefetch, polling or focus-triggered record retrieval.

The screen displays backend-returned values, record classifications, response ID and
disclosure semantics. APPLICATION_COMPLETE means application processing completed;
the disclosure ledger does not prove network delivery or human receipt/viewing. No
total count is inferred. A full page permits a next-page request that may be empty.
Selection changes, errors and session rejection clear the displayed values. Requests
already submitted may have been processed even if a late response is discarded.

An approved database must separately contain compatible fictional resources and
BusinessRecord rows. The identity-only bootstrap does not create them; the frontend
does not seed or fabricate them. Select an existing same-department non-CRITICAL
resource for a permitted read, and an existing cross-department resource without
ownership or a valid read grant for a denied read, subject to current backend policy.
Admin **Reload current data** refreshes disclosure, detection, risk and incident views.
No record values, scores, permissions or detection results are synthesized by this UI.
