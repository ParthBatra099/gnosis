# Unit 8 frontend authentication cutover

Unit 10B adds My sessions and Super-Admin employee-session management. Session
revocation uses cookie/CSRF transport, explicit confirmation and a required reason.
One-time recovery codes are retained in memory across temporary profile failures;
workspace access still requires profile validation, and protected 401 clears them.
Recent-TOTP prompts remain deferred. See the backend Unit 10B report for contracts.

The inspected source of truth is `backend/app/api/v1/auth.py`, its request schemas,
`authentication_transport.py`, `mfa_workflows.py`, `api/deps.py`, and the backend
authentication/authority/administrative/organization-management documents.
Unit 8A's `UserRead.organization_role` is the canonical profile contract.

## Exact HTTP contract

All paths are relative to the configured `VITE_API_BASE_URL` (no `/api/v1` prefix).
Every request uses Axios `withCredentials: true`. The browser manages cookies;
the frontend neither reads cookies nor supplies Authorization/bearer tokens.

| Operation | Method/path and body | Successful response / effect |
|---|---|---|
| CSRF bootstrap/refresh | GET `/auth/csrf`, no body | `{csrf_token}`; server sets CSRF cookie |
| Password | POST `/auth/login`, `{email,password,intent:"login" or "recover"}` | `{next_step,challenge_id,challenge_secret}` only |
| Begin initial/replacement setup | POST `/auth/mfa/enroll`, `{challenge_id,challenge_secret}` | `{next_step:"VERIFY_ENROLLMENT",provisioning_uri,qr_payload}` |
| Verify enrolled authenticator | POST `/auth/mfa/verify`, `{challenge_id,challenge_secret,code}` | `{authenticated:true,csrf_token}`; server sets session and bound CSRF cookies |
| Verify initial/replacement setup | POST `/auth/mfa/enroll/verify`, same verification body | `{authenticated:true,csrf_token,recovery_codes:[...]}`; server sets cookies |
| Verify recovery | POST `/auth/recovery/verify`, same verification body, single recovery code | `{next_step:"REPLACEMENT_ENROLLMENT",challenge_id,challenge_secret}`; no session |
| Restore/validate profile | GET `/auth/me`, no body | `{id,name,email,role,organization_role,department_id,active}` |
| Sign out | POST `/auth/logout`, no body | 204; revokes current session and removes cookies |

Password `next_step` values are MFA_VERIFICATION, MFA_ENROLLMENT or ACCOUNT_RECOVERY.
An unenrolled account requesting recovery can receive MFA_ENROLLMENT. Recovery
alone must return REPLACEMENT_ENROLLMENT and cannot establish frontend authentication.
The returned `next_step` is not sent back as a request claim: challenge bodies
forbid extra fields. Full application access follows verified MFA AND `/auth/me`.
New recovery inventory is shown before workspace entry and cleared on acknowledgement.
`/auth/logout-all` exists in the backend but no new UI for it is introduced here.

## Transport and deployment requirements

The backend owns Secure, HttpOnly, SameSite=Strict, Path=/ host-only cookies
`__Host-gnosis_session` and `__Host-gnosis_csrf`. The frontend cannot weaken them.
Before each unsafe request (POST, PUT, PATCH, DELETE, or other non-safe method),
the shared client obtains a CSRF token if absent and sends `X-CSRF-Token`.
Completion replaces the anonymous header value with the returned session-bound
value. Refreshing a page bootstraps CSRF on the next unsafe request. A 403 clears
the cached header for the next explicit attempt; mutations are never auto-replayed.
Authentication responses are no-store as enforced by the backend.

Configure reviewed HTTPS frontend/API addresses, the exact frontend origin in
`AUTH_ALLOWED_ORIGINS`, credentialed CORS and a compatible same-site topology.
The existing development fallback `http://localhost:8000` is retained, but cannot
authenticate under the backend's HTTPS enforcement. No credentials/keys/origin
allowlists or proxy protections are changed by this unit.

Important topology constraint: GET `/auth/csrf` requires an exact Origin header.
Cross-origin browser Axios requests supply Origin automatically. A same-origin
GET does not reliably include Origin, and scripts cannot set that forbidden
header. The supported deployment for this frontend therefore needs a reviewed
HTTPS, cross-origin, same-site API configuration. A same-origin reverse-proxy
deployment needs separate review of this backend contract before deployment;
the frontend does not spoof Origin or weaken CSRF to accommodate it. No real
deployment addresses or live browser authentication were assumed or tested here.

## States, errors and secrets

`AuthController` is the state machine used directly by `AuthProvider` and the
tests. Separate stages cover restoration, password, TOTP, enrollment, recovery,
replacement, enrollment unavailable, recovery-code acknowledgement, authenticated
workspace and session ended. Restricted challenge secrets are private in-memory
controller values. Password/code inputs clear on submission and stage transitions.
Provisioning material is rendered locally as manual authenticator settings
(account/key/issuer/algorithm/digits/interval); no external QR service or new QR
dependency is used. Material clears after verification, cancellation or sign-out.
Recovery values are not retained for retry. They are shown only when newly issued.
No credential/session/provisioning value is written to localStorage/sessionStorage.
The obsolete localStorage bearer key is removed without reading its contents;
storage-disabled browsers still use cookie authentication.

The default backend has no trusted first-enrollment authorizer. Initial setup
401 responses show enrollment unavailable and describe this limitation, while
acknowledging that expired/invalid challenges produce the same neutral response.
No denial is interpreted as a specific credential-validation result. There is no
frontend bootstrap, fabricated approval, password-only fallback or fake success.
Invalid/expired/consumed challenge messages remain neutral. A 429 instructs users
to wait. Other failures leave the user unauthenticated or within their restricted
challenge. If the completion response is lost, secret redisclosure is not promised;
restart through the supported backend workflow.

Restoration calls `/auth/me` without requiring any browser token. Focus/visibility
changes revalidate authenticated sessions; a backend 401 on a protected operation
clears identity and temporary material and returns to sign-in. Public auth POST
denials remain challenge errors. Late asynchronous responses cannot restore a
cancelled/logged-out identity. Logout calls server revocation and clears local
state even on failure, with an explicit warning when revocation was not confirmed.

## Canonical role presentation

Only exact SUPER_ADMIN, DEPARTMENT_ADMIN and EMPLOYEE from the persisted profile's
`organization_role` select navigation. Legacy `role` is never an authority input.
Null, absent or unrecognized canonical roles have no role-specific links and
are routed to an explicit identity-unavailable screen. In normal backend behavior,
unmapped identities already fail persisted-session validation with 401.

Both administrator roles may enter the existing administrative console and keep
employee workspace/personal-request links. Only Super Admin sees organization
identity/assignment placeholders; Department Admin sees assigned-department
presentation. New organization controls remain disabled pending Unit 9, rather
than inventing screens or APIs. Existing unfinished navigation remains disabled.
No department IDs/assignments are inferred from home department or role. Backend
Units 3/4/7 still decide scope, self-approval restrictions and every operation's
authorization. Navigation grants no business-data access. Existing dashboard/demo
content and resource-access semantics are outside this integration.

## Verification

From `frontend`:

```powershell
npm test
npm run build
```

Tests use Node's built-in test runner and the already installed TypeScript
compiler, transpiling source in memory. `tests/register.mjs` is test-only and
requires Node with `module.registerHooks` support (verified with Node 25.6.1).
State-machine tests exercise the exact controller used by the provider; Axios
adapter tests verify cookie configuration, CSRF rotation/refresh and exact request
bodies; React server rendering checks guards, navigation and authentication screens.
No network request, database or backend process is needed. These are not live
browser cookie/CORS/TLS or backend MFA verification tests. A reviewed deployment
still needs that smoke test with real trusted enrollment integration and its
approved TLS/origin/proxy configuration.

Backend files and its isolated launcher remain untouched, so backend tests are
not rerun. No migration, backfill, database command or dependency installation
is performed. The package manifest adds only a test command; the lockfile is unchanged.

Final checks: `npm test` passed all 33 tests; `npm run build` passed TypeScript
and the Vite production build; targeted ESLint on the client, controller,
provider, login, role helpers and route modules passed. `git diff --check` passed
with Git line-ending notices only. Initial implementation checks caught and
corrected nullable Promise typing, a TypeScript parameter-property incompatibility
and test-loader dependency resolution; no unrelated application fix was made.

## Exact file inventory

Updated:

- `frontend/package.json` — dependency-free test command only.
- `frontend/src/api/auth.ts` — exact cookie/challenge authentication operations.
- `frontend/src/api/client.ts` — cookie transport, in-memory CSRF, rejection notification.
- `frontend/src/context/AuthProvider.tsx` — controller subscription and session lifecycle.
- `frontend/src/types/auth.ts` — challenge, session, canonical-role and UI state types.
- `frontend/src/types/api.ts` — nullable canonical identity in the profile type.
- `frontend/src/utils/constants.ts` — remove obsolete bearer-storage constant.
- `frontend/src/utils/roles.ts` — exact canonical-role presentation, no legacy fallback.
- `frontend/src/pages/auth/Login.tsx` — password/MFA/manual enrollment/recovery screens.
- `frontend/src/pages/auth/Login.css` — setup material and secondary-control styling.
- `frontend/src/routes/ProtectedRoute.tsx` — authentication and canonical-role guards.
- `frontend/src/routes/AppRoutes.tsx` — canonical redirects and identity-unavailable route.
- `frontend/src/components/layout/Sidebar.tsx` — canonical navigation and employee links.
- `frontend/src/components/layout/Topbar.tsx` — canonical identity label.
- `frontend/src/pages/employee/EmployeeHome.tsx` — canonical organizational-role labels.
- `frontend/src/pages/admin/AdminHome.tsx` — canonical organizational-role label.

Added:

- `frontend/src/context/authController.ts` — testable authentication state machine.
- `frontend/tests/authentication.test.mjs` — 33 frontend integration/contract checks.
- `frontend/tests/register.mjs` — in-memory TypeScript/TSX test loader.
- `frontend/AUTHENTICATION.md` — inspected contract, deployment constraints and this report.

Before editing, hashes were captured for all 193 Git-visible files, including
pre-existing untracked backend work. Final comparison: 16 intended frontend files
updated, 4 frontend files added, 177 existing files unchanged, none removed.
Every backend file, Phase 1 isolation guard and Unit 1–8A change is byte-for-byte
preserved. Ignored production build output and TypeScript build metadata are
generated by the requested build; no lockfile or dependency change is made.
