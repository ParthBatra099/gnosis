import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router-dom';
import { AxiosError } from 'axios';
import { AuthController } from '../src/context/authController.ts';
import { apiClient, setCsrfToken } from '../src/api/client.ts';
import { authApi } from '../src/api/auth.ts';
import { AuthContext } from '../src/context/AuthContext.ts';
import { ProtectedRoute } from '../src/routes/ProtectedRoute.tsx';
import { Sidebar } from '../src/components/layout/Sidebar.tsx';
import { Login } from '../src/pages/auth/Login.tsx';
import { canonicalRole, canPresentRoute, getDefaultRouteForUser } from '../src/utils/roles.ts';

const user = role => ({ id: 'fictional', name: 'Fixture', email: 'fixture@example.invalid', role: 'ADMIN', organization_role: role, department_id: 'fixture-dept', active: true });
const ticket = purpose => ({ next_step: purpose, challenge_id: 'fictional-challenge', challenge_secret: 'test-only-restricted-secret' });
const provisioning = { next_step: 'VERIFY_ENROLLMENT', provisioning_uri: 'otpauth://totp/Fixture?secret=FICTIONALSECRET&issuer=GNOSIS', qr_payload: 'otpauth://totp/Fixture?secret=FICTIONALSECRET&issuer=GNOSIS' };
const session = { authenticated: true, csrf_token: 'fictional-session-csrf' };
const failure = status => Object.assign(new Error('Fixture denial'), { response: { status } });
const mockApi = overrides => ({ login: async () => ticket('MFA_VERIFICATION'), profile: async () => user('EMPLOYEE'), enroll: async () => provisioning, verify: async () => session, recover: async () => ticket('REPLACEMENT_ENROLLMENT'), logout: async () => {}, ...overrides });
const controller = overrides => new AuthController(mockApi(overrides));
const authenticated = state => state.stage === 'authenticated' && state.user !== null;
const rejectNetwork = async () => { throw new Error('Frontend tests must not contact a real service'); };
apiClient.defaults.adapter = rejectNetwork;
afterEach(() => { setCsrfToken(null); apiClient.defaults.adapter = rejectNetwork; });

test('password success produces only a restricted MFA state', async () => {
  let profileCalls = 0;
  const auth = controller({ profile: async () => { profileCalls++; return user('EMPLOYEE'); } });
  await auth.login('fixture@example.invalid', 'fictional-password');
  assert.equal(auth.snapshot().stage, 'mfa');
  assert.equal(auth.snapshot().user, null);
  assert.equal(profileCalls, 0);
  assert.equal(authenticated(auth.snapshot()), false);
  assert.equal(JSON.stringify(auth.snapshot()).includes('restricted-secret'), false);
});
test('MFA completion requires successful persisted-session profile retrieval', async () => {
  const auth = controller();
  await auth.login('fixture', 'password');
  await auth.verify('123456');
  assert.equal(authenticated(auth.snapshot()), true);
  assert.equal(auth.snapshot().user.organization_role, 'EMPLOYEE');
});
for (const description of ['invalid', 'expired', 'consumed']) {
  test(`${description} challenge remains unauthenticated with a neutral error`, async () => {
    const auth = controller({ verify: async () => { throw failure(401); } });
    await auth.login('fixture', 'password');
    await auth.verify('123456');
    assert.equal(authenticated(auth.snapshot()), false);
    assert.match(auth.snapshot().message, /invalid, expired or already used/);
  });
}
test('first enrollment denial explains absent trusted authorization without bypass', async () => {
  let verifyCalls = 0;
  const auth = controller({ login: async () => ticket('MFA_ENROLLMENT'), enroll: async () => { throw failure(401); }, verify: async () => { verifyCalls++; return session; } });
  await auth.login('fixture', 'password');
  await auth.startEnrollment();
  assert.equal(auth.snapshot().stage, 'enrollment-unavailable');
  assert.match(auth.snapshot().message, /Trusted independent onboarding is not configured/);
  assert.equal(auth.snapshot().provisioningUri, null);
  await auth.verify('123456');
  assert.equal(verifyCalls, 0);
  assert.equal(authenticated(auth.snapshot()), false);
});
test('authorized enrollment waits for TOTP and displays newly issued recovery codes once', async () => {
  const auth = controller({ login: async () => ticket('MFA_ENROLLMENT'), verify: async () => ({ ...session, recovery_codes: ['fictional-code-A', 'fictional-code-B'] }) });
  await auth.login('fixture', 'password');
  await auth.startEnrollment();
  assert.equal(auth.snapshot().provisioningUri, provisioning.provisioning_uri);
  assert.equal(authenticated(auth.snapshot()), false);
  await auth.verify('123456');
  assert.equal(auth.snapshot().provisioningUri, null);
  assert.equal(auth.snapshot().stage, 'recovery-codes');
  assert.equal(authenticated(auth.snapshot()), false);
  auth.finishRecoveryCodes();
  assert.deepEqual(auth.snapshot().recoveryCodes, []);
  assert.equal(authenticated(auth.snapshot()), true);
});
test('password plus recovery code leads only to replacement setup, then new TOTP/session', async () => {
  const seen = [];
  const auth = controller({
    login: async (...args) => { seen.push(args); return ticket('ACCOUNT_RECOVERY'); },
    recover: async (input, code) => { seen.push([input.next_step, code]); return ticket('REPLACEMENT_ENROLLMENT'); },
    enroll: async input => { seen.push(input.next_step); return provisioning; },
  });
  await auth.login('fixture', 'password', true);
  assert.equal(auth.snapshot().stage, 'recovery');
  await auth.verify('fictional-once-only-code');
  assert.equal(auth.snapshot().stage, 'replacement');
  assert.equal(auth.snapshot().user, null);
  assert.equal(JSON.stringify(auth.snapshot()).includes('fictional-once-only-code'), false);
  await auth.startEnrollment();
  await auth.verify('654321');
  assert.equal(authenticated(auth.snapshot()), true);
  assert.deepEqual(seen, [['fixture', 'password', true], ['ACCOUNT_RECOVERY', 'fictional-once-only-code'], 'REPLACEMENT_ENROLLMENT']);
});
test('replacement verification cannot skip setup; recovery cannot return an authenticated session', async () => {
  let verifies = 0;
  const auth = controller({ login: async () => ticket('ACCOUNT_RECOVERY'), recover: async () => session, verify: async () => { verifies++; return session; } });
  await auth.login('fixture', 'password', true);
  await auth.verify('fictional-code');
  assert.equal(authenticated(auth.snapshot()), false);
  assert.equal(verifies, 0);
});
test('profile failure after MFA never leaves a falsely authenticated state', async () => {
  const auth = controller({ profile: async () => { throw failure(503); } });
  await auth.login('fixture', 'password');
  await auth.verify('123456');
  assert.equal(auth.snapshot().user, null);
  assert.equal(authenticated(auth.snapshot()), false);
  assert.equal(auth.snapshot().provisioningUri, null);
});
test('password-only or malformed session responses cannot authenticate', async () => {
  const auth = controller({ verify: async () => ({ access_token: 'forbidden-legacy-response' }) });
  await auth.login('fixture', 'password');
  await auth.verify('123456');
  assert.equal(authenticated(auth.snapshot()), false);
});
test('session restoration checks the backend without a local token', async () => {
  const auth = controller();
  await auth.restore();
  assert.equal(authenticated(auth.snapshot()), true);
});
for (const code of [401, 503]) {
  test(`restoration failure ${code} remains unauthenticated`, async () => {
    const auth = controller({ profile: async () => { throw failure(code); } });
    await auth.restore();
    assert.equal(auth.snapshot().stage, 'login');
    assert.equal(auth.snapshot().user, null);
  });
}
test('expired, revoked or generation-invalidated session rejection clears identity and secrets', async () => {
  const auth = controller();
  const disconnect = auth.connect();
  await auth.restore();
  apiClient.defaults.adapter = async config => { throw new AxiosError('Rejected', 'ERR_BAD_REQUEST', config, null, { status: 401, data: {}, config }); };
  await assert.rejects(apiClient.get('/protected-operation'));
  assert.equal(auth.snapshot().stage, 'session-ended');
  assert.equal(auth.snapshot().user, null);
  assert.deepEqual(auth.snapshot().recoveryCodes, []);
  disconnect();
});
test('focus revalidation fails closed and logout clears state and calls backend', async () => {
  let fail = false, logouts = 0;
  const auth = controller({ profile: async () => { if (fail) throw failure(401); return user('EMPLOYEE'); }, logout: async () => { logouts++; } });
  await auth.restore();
  fail = true;
  await auth.refresh();
  assert.equal(auth.snapshot().stage, 'session-ended');
  fail = false;
  await auth.restore();
  await auth.logout();
  assert.equal(logouts, 1);
  assert.equal(auth.snapshot().user, null);
  assert.equal(auth.snapshot().stage, 'login');
});
test('logout network failure clears local state but does not claim successful revocation', async () => {
  const auth = controller({ logout: async () => { throw failure(503); } });
  await auth.restore();
  await auth.logout();
  assert.equal(auth.snapshot().user, null);
  assert.match(auth.snapshot().message, /revocation was not confirmed/);
});
test('late profile response cannot undo logout or session rejection', async () => {
  let resolve;
  const auth = controller({ profile: () => new Promise(done => { resolve = done; }) });
  const pending = auth.restore();
  auth.sessionEnded();
  resolve(user('SUPER_ADMIN'));
  await pending;
  assert.equal(auth.snapshot().stage, 'session-ended');
  assert.equal(auth.snapshot().user, null);
});
test('late verification response cannot undo cancellation', async () => {
  let resolve;
  const auth = controller({ verify: () => new Promise(done => { resolve = done; }) });
  await auth.login('fixture', 'password');
  const pending = auth.verify('123456');
  auth.restart();
  resolve(session);
  await pending;
  assert.equal(auth.snapshot().stage, 'login');
  assert.equal(auth.snapshot().user, null);
});
test('rate limiting provides a retry message without authentication', async () => {
  const auth = controller({ login: async () => { throw failure(429); } });
  await auth.login('fixture', 'password');
  assert.match(auth.snapshot().message, /Too many attempts/);
  assert.equal(authenticated(auth.snapshot()), false);
});

function render(element, value) {
  return renderToStaticMarkup(React.createElement(MemoryRouter, null,
    React.createElement(AuthContext.Provider, { value }, element)));
}
const context = overrides => ({ ...controller().snapshot(), stage: 'authenticated', user: user('EMPLOYEE'), isAuthenticated: true, isLoading: false,
  logout: async () => {}, login: async () => {}, verify: async () => {}, startEnrollment: async () => {}, restart: () => {}, finishRecoveryCodes: () => {}, ...overrides });
test('protected routes do not render children without a validated frontend session', () => {
  const secret = React.createElement('div', null, 'protected-fixture');
  const wrapped = React.createElement(ProtectedRoute, null, secret);
  assert.doesNotMatch(render(wrapped, context({ isAuthenticated: false, user: null })), /protected-fixture/);
  assert.doesNotMatch(render(wrapped, context({ user: user(null) })), /protected-fixture/);
  assert.match(render(wrapped, context()), /protected-fixture/);
});
for (const role of ['SUPER_ADMIN', 'DEPARTMENT_ADMIN', 'EMPLOYEE']) {
  test(`canonical ${role} controls navigation and permits ordinary employee functionality`, () => {
    const current = user(role);
    assert.equal(canPresentRoute(current), true);
    const admin = role !== 'EMPLOYEE';
    assert.equal(canPresentRoute(current, ['SUPER_ADMIN', 'DEPARTMENT_ADMIN']), admin);
    assert.equal(getDefaultRouteForUser(current), admin ? '/admin' : '/employee');
    const sidebar = render(React.createElement(Sidebar, { mobileOpen: false, onCloseMobile() {} }), context({ user: current }));
    assert.equal(sidebar.includes('Organization identities'), role === 'SUPER_ADMIN');
    assert.equal(sidebar.includes('Assigned departments'), role === 'DEPARTMENT_ADMIN');
    assert.equal(sidebar.includes('My employee workspace'), admin);
    assert.match(sidebar, /Access Requests/);
    const protectedAdmin = React.createElement(ProtectedRoute, { allowedRoles: ['SUPER_ADMIN', 'DEPARTMENT_ADMIN'] }, 'admin-fixture');
    assert.equal(render(protectedAdmin, context({ user: current })).includes('admin-fixture'), admin);
  });
}
for (const legacy of ['ADMIN', 'MANAGER', 'SECURITY_OFFICER', 'SUPER_ADMIN']) {
  test(`legacy ${legacy} cannot supply canonical authority when role is null or missing`, () => {
    for (const role of [null, undefined, 'ADMIN', 'super_admin']) {
      const current = { ...user(role), role: legacy };
      assert.equal(canonicalRole(current), null);
      assert.equal(canPresentRoute(current), false);
      assert.equal(getDefaultRouteForUser(current), '/identity-unavailable');
      const sidebar = render(React.createElement(Sidebar, { mobileOpen: false }), context({ user: current }));
      assert.doesNotMatch(sidebar, /href=/);
    }
  });
}
test('rendered login stages show challenge, recovery and unavailable enrollment accurately', () => {
  for (const [stage, text] of [['mfa', 'Verify your authenticator'], ['recovery', 'Use a recovery code'], ['replacement', 'Replace your authenticator'], ['enrollment-unavailable', 'Enrollment unavailable']]) {
    const markup = render(React.createElement(Login), context({ stage, user: null, isAuthenticated: false }));
    assert.match(markup, new RegExp(text));
    assert.doesNotMatch(markup, /id="password"/);
  }
});
test('secrets use manual local setup and are not written to browser storage or external QR services', () => {
  function sources(directory) {
    return readdirSync(directory, { withFileTypes: true }).flatMap(entry => entry.isDirectory() ? sources(new URL(entry.name + '/', directory)) : /\.(tsx?|css)$/.test(entry.name) ? [readFileSync(new URL(entry.name, directory), 'utf8')] : []);
  }
  const source = sources(new URL('../src/', import.meta.url)).join('\n');
  assert.doesNotMatch(source, /(?:localStorage|sessionStorage)\.(?:setItem|getItem)|Authorization\s*=|Bearer\s/);
  const markup = render(React.createElement(Login), context({ stage: 'replacement', user: null, isAuthenticated: false, provisioningUri: provisioning.provisioning_uri }));
  assert.match(markup, /FICTIONALSECRET/);
  assert.doesNotMatch(markup, /<img|otpauth:\/\//);
});

test('actual Axios transport uses cookies and exact challenge bodies; all unsafe methods carry CSRF', async () => {
  const requests = [];
  apiClient.defaults.adapter = async config => {
    requests.push(config);
    const data = config.url === '/auth/csrf' ? { csrf_token: 'anonymous-csrf' } : config.url === '/auth/login' ? ticket('MFA_VERIFICATION') : config.url === '/auth/me' ? user('EMPLOYEE') : session;
    return { status: 200, data, headers: {}, config };
  };
  await authApi.login('fixture@example.invalid', 'fixture-password', true);
  await authApi.enroll(ticket('MFA_ENROLLMENT'));
  await authApi.verify(ticket('MFA_VERIFICATION'), '123456', false);
  setCsrfToken('session-bound-csrf');
  await authApi.verify(ticket('REPLACEMENT_ENROLLMENT'), '654321', true);
  await authApi.recover(ticket('ACCOUNT_RECOVERY'), 'fictional-code');
  await authApi.profile();
  await apiClient.patch('/fixture', { reason: 'test' });
  await apiClient.delete('/fixture');
  await authApi.logout();
  assert.equal(requests.filter(r => r.url === '/auth/csrf').length, 1);
  for (const config of requests) {
    assert.equal(config.withCredentials, true);
    assert.equal(config.headers.has('Authorization'), false);
    if (!['get', 'head', 'options'].includes(config.method)) assert.ok(config.headers.get('X-CSRF-Token'));
  }
  assert.deepEqual(JSON.parse(requests.find(r => r.url === '/auth/login').data), { email: 'fixture@example.invalid', password: 'fixture-password', intent: 'recover' });
  for (const request of requests.filter(r => r.url.startsWith('/auth/mfa') || r.url === '/auth/recovery/verify')) {
    const body = JSON.parse(request.data);
    assert.equal(body.next_step, undefined);
    assert.equal(body.challenge_id, 'fictional-challenge');
    assert.equal(body.challenge_secret, 'test-only-restricted-secret');
  }
  assert.equal(requests.find(r => r.url === '/fixture').headers.get('X-CSRF-Token'), 'session-bound-csrf');
});
test('public MFA denial is not a session-rejection event; expired CSRF is refreshed without replay', async () => {
  const auth = controller();
  const disconnect = auth.connect();
  await auth.login('fixture', 'password');
  let posts = 0, gets = 0;
  apiClient.defaults.adapter = async config => {
    if (config.url === '/auth/csrf') { gets++; return { status: 200, data: { csrf_token: 'csrf-' + gets }, config }; }
    posts++;
    throw new AxiosError('Denied', 'ERR_BAD_REQUEST', config, null, { status: posts === 1 ? 401 : 403, data: {}, config });
  };
  await assert.rejects(authApi.verify(ticket('MFA_VERIFICATION'), '123456', false));
  assert.equal(auth.snapshot().stage, 'mfa');
  await assert.rejects(apiClient.post('/fixture'));
  assert.equal(posts, 2);
  await assert.rejects(apiClient.post('/fixture'));
  assert.equal(posts, 3);
  assert.equal(gets, 2);
  disconnect();
});

test('controller and real API client perform password, MFA, profile and server logout in order', async () => {
  const requests = [];
  apiClient.defaults.adapter = async config => {
    requests.push(config);
    const data = config.url === '/auth/csrf' ? { csrf_token: 'initial-csrf' } :
      config.url === '/auth/login' ? ticket('MFA_VERIFICATION') :
      config.url === '/auth/mfa/verify' ? session :
      config.url === '/auth/me' ? user('DEPARTMENT_ADMIN') : null;
    return { status: config.url === '/auth/logout' ? 204 : 200, data, headers: {}, config };
  };
  const auth = new AuthController();
  await auth.login('fixture@example.invalid', 'fixture-password');
  assert.equal(auth.snapshot().user, null);
  assert.equal(requests.some(r => r.url === '/auth/me'), false);
  await auth.verify('123456');
  assert.equal(authenticated(auth.snapshot()), true);
  assert.equal(auth.snapshot().user.organization_role, 'DEPARTMENT_ADMIN');
  await auth.logout();
  assert.equal(auth.snapshot().user, null);
  assert.deepEqual(requests.map(r => r.url), ['/auth/csrf', '/auth/login', '/auth/mfa/verify', '/auth/me', '/auth/logout']);
  assert.equal(requests.at(-1).headers.get('X-CSRF-Token'), session.csrf_token);
});
