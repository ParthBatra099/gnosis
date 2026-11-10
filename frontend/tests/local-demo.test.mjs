import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router-dom';
import { AxiosError } from 'axios';
import { apiClient, enableLocalDemoTransport, DEMO_AUTH_MODE, setCsrfToken } from '../src/api/client.ts';
import { demoApi } from '../src/demo/api.ts';
import { DemoController } from '../src/demo/controller.ts';
import { DemoFrame, DEMO_WARNING } from '../src/demo/DemoFrame.tsx';
import { DemoLogin } from '../src/demo/DemoLogin.tsx';
import { AuthContext } from '../src/context/AuthContext.ts';
import { AuthController } from '../src/context/authController.ts';
import { Sidebar } from '../src/components/layout/Sidebar.tsx';
import { ProtectedRoute } from '../src/routes/ProtectedRoute.tsx';
import { getDefaultRouteForUser, canPresentRoute } from '../src/utils/roles.ts';

const user = role => ({ id: 'fictional-demo', name: 'Fictional Person', email: 'demo-person@example.com',
  role: 'ADMIN', organization_role: role, department_id: 'fictional-home', active: true });
const failure = status => Object.assign(new Error('Fictional denial'), { response: { status } });
const mockApi = overrides => ({ login: async () => {}, profile: async () => user('EMPLOYEE'), logout: async () => {}, ...overrides });
const rejectNetwork = async () => { throw new Error('Tests must never contact a real service'); };
enableLocalDemoTransport('https://localhost:8443');
apiClient.defaults.adapter = rejectNetwork;
afterEach(() => { setCsrfToken(null); apiClient.defaults.adapter = rejectNetwork; });
const read = path => readFileSync(new URL(path, import.meta.url), 'utf8');
function adapter(handler) {
  apiClient.defaults.adapter = async config => {
    const [status, data] = handler(config);
    const response = { config, status, data, statusText: String(status), headers: {} };
    if (status >= 400) throw new AxiosError('Fictional response', undefined, config, undefined, response);
    return response;
  };
}
const csrf = { auth_mode: DEMO_AUTH_MODE, csrf_token: 'fictional-csrf' };

test('dedicated demo entry cannot be selected by normal startup or an MFA fallback', () => {
  assert.match(read('../demo.html'), /src\/demo\/main.tsx/);
  assert.doesNotMatch(read('../index.html'), /demo\/main/);
  assert.doesNotMatch(read('../src/main.tsx'), /DemoProvider|enableLocalDemoTransport|VITE_DEMO/);
  assert.match(read('../src/demo/main.tsx'), /enableLocalDemoTransport/);
  assert.match(read('../src/demo/main.tsx'), /hashRouting loginElement={<DemoLogin/);
  assert.doesNotMatch(read('../vite.config.ts'), /demo.html|demo\/main/);
});

test('demo API requires explicit loopback HTTPS configuration', () => {
  for (const url of ['http://localhost:8443', 'https://public.example.com', 'https://localhost/path', 'https://user:pass@localhost'])
    assert.throws(() => enableLocalDemoTransport(url));
  assert.equal(apiClient.defaults.withCredentials, true);
});

test('password login uses mode-bound CSRF and profile contract without MFA requests', async () => {
  const calls = [];
  adapter(config => {
    calls.push(config);
    if (config.url === '/auth/csrf') return [200, csrf];
    if (config.url === '/health') return [200, { auth_mode: DEMO_AUTH_MODE, demo_mode: true }];
    if (config.url === '/auth/login') return [200, { ...csrf, authenticated: true }];
    if (config.url === '/auth/me') return [200, user('EMPLOYEE')];
    throw new Error('Unexpected endpoint');
  });
  const auth = new DemoController();
  await auth.login('demo-person@example.com', 'Fictional-secret');
  assert.equal(auth.snapshot().stage, 'authenticated');
  const login = calls.find(c => c.url === '/auth/login');
  assert.deepEqual(JSON.parse(login.data), { email: 'demo-person@example.com', password: 'Fictional-secret', intent: 'login' });
  assert.equal(login.headers.get('X-CSRF-Token'), 'fictional-csrf');
  assert.equal(login.headers.get('Authorization'), undefined);
  assert(!calls.some(c => /mfa|recovery/.test(c.url)));
  assert(!JSON.stringify(auth.snapshot()).includes('Fictional-secret'));
  assert.equal(auth.snapshot().provisioningUri, null);
  assert.deepEqual(auth.snapshot().recoveryCodes, []);
});

for (const denied of [401, 429, 503]) test(`failed demo login ${denied} grants no profile access`, async () => {
  let profiles = 0;
  const auth = new DemoController(mockApi({ login: async () => { throw failure(denied); },
    profile: async () => { profiles++; return user('SUPER_ADMIN'); } }));
  await auth.login('fictional', 'fictional');
  assert.equal(auth.snapshot().user, null);
  assert.equal(profiles, 0);
  assert(auth.snapshot().message);
});

test('wrong backend mode blocks restoration before querying /me', async () => {
  const paths = [];
  adapter(config => { paths.push(config.url); return [200, { csrf_token: 'normal-csrf' }]; });
  const auth = new DemoController();
  await auth.restore();
  assert.equal(auth.snapshot().stage, 'login');
  assert.deepEqual(paths, ['/health']);
});

test('profile refresh checks live demo mode without rotating the CSRF cookie', async () => {
  const paths = [];
  adapter(config => {
    paths.push(config.url);
    if (config.url === '/health') return [200, { auth_mode: DEMO_AUTH_MODE, demo_mode: true }];
    if (config.url === '/auth/me') return [200, user('EMPLOYEE')];
    throw new Error('Unexpected CSRF rotation');
  });
  assert.equal((await demoApi.profile()).organization_role, 'EMPLOYEE');
  assert.deepEqual(paths, ['/health', '/auth/me']);
});

test('an MFA challenge or false demo mode cannot masquerade as password-only login', async () => {
  for (const payload of [{ next_step: 'MFA_VERIFICATION' }, { authenticated: true, auth_mode: 'NORMAL' },
    { ...csrf, authenticated: true, recovery_codes: ['fictional'] }]) {
    adapter(config => config.url === '/auth/csrf' ? [200, csrf] : [200, payload]);
    await assert.rejects(demoApi.login('fictional', 'fictional'));
  }
});

test('restoration accepts a real profile and refresh uses current canonical identity', async () => {
  let role = 'EMPLOYEE';
  const auth = new DemoController(mockApi({ profile: async () => user(role) }));
  await auth.restore();
  assert.equal(auth.snapshot().stage, 'authenticated');
  role = 'DEPARTMENT_ADMIN';
  await auth.refresh();
  assert.equal(auth.snapshot().user.organization_role, 'DEPARTMENT_ADMIN');
});

for (const denied of [401, 503]) test(`protected rejection ${denied} clears the current demo identity`, async () => {
  const auth = new DemoController(mockApi());
  await auth.restore();
  const disconnect = auth.connect();
  try {
    adapter(() => [denied, { detail: 'Fictional session rejection' }]);
    await assert.rejects(apiClient.get('/resources/fictional/records'));
    assert.equal(auth.snapshot().user, null);
    assert.equal(auth.snapshot().stage, 'session-ended');
  } finally { disconnect(); }
});

test('logout clears identity and reports unconfirmed server revocation', async () => {
  const auth = new DemoController(mockApi({ logout: async () => { throw failure(500); } }));
  await auth.restore();
  await auth.logout();
  assert.equal(auth.snapshot().user, null);
  assert.match(auth.snapshot().message, /revocation was not confirmed/);
});

test('logout uses the demo CSRF and logout URL, no secret body', async () => {
  const calls = [];
  adapter(config => { calls.push(config); return config.url === '/auth/csrf' ? [200, csrf] : [204, null]; });
  await demoApi.logout();
  assert.deepEqual(calls.map(c => c.url), ['/auth/csrf', '/auth/logout']);
  assert.equal(calls[1].headers.get('X-CSRF-Token'), 'fictional-csrf');
  assert.equal(calls[1].data, undefined);
});

test('late restoration cannot resurrect a locally signed-out demo session', async () => {
  let finish;
  const auth = new DemoController(mockApi({ profile: () => new Promise(resolve => { finish = resolve; }) }));
  const pending = auth.restore();
  await auth.logout();
  finish(user('SUPER_ADMIN'));
  await pending;
  assert.equal(auth.snapshot().user, null);
});

test('persistent warning encloses authenticated, signed-out and error screens', () => {
  for (const child of ['Sign in', 'Fictional dashboard', 'Session expired']) {
    const html = renderToStaticMarkup(React.createElement(DemoFrame, null, React.createElement('main', null, child)));
    assert(html.includes(DEMO_WARNING));
    assert(html.includes(child));
  }
});

function renderAuth(child, role, extra = {}) {
  return renderToStaticMarkup(React.createElement(AuthContext.Provider, { value: {
    user: user(role), stage: 'authenticated', isAuthenticated: true, isLoading: false, busy: false,
    message: null, logout: async () => {}, login: async () => {}, ...extra,
  } }, React.createElement(MemoryRouter, null, child)));
}
for (const role of ['EMPLOYEE', 'DEPARTMENT_ADMIN', 'SUPER_ADMIN', null]) test(`demo presentation honors canonical role ${role}`, () => {
  const html = renderAuth(React.createElement(Sidebar, { mobileOpen: false, onCloseMobile() {} }), role);
  assert.equal(html.includes('Organization identities'), role === 'SUPER_ADMIN');
  assert.equal(canPresentRoute(user(role), ['SUPER_ADMIN']), role === 'SUPER_ADMIN');
  assert.equal(getDefaultRouteForUser(user(role)), role === null ? '/identity-unavailable' : role === 'EMPLOYEE' ? '/employee' : '/admin');
  if (role === 'EMPLOYEE') assert(!html.includes('Security Events'));
  if (role === null) assert.equal(renderAuth(React.createElement(ProtectedRoute, null, 'Forbidden'), role).includes('Forbidden'), false);
});

test('demo login presents loading and failure states without authenticator claims', () => {
  const loading = renderAuth(React.createElement(DemoLogin), null, { isAuthenticated: false, isLoading: true });
  assert.match(loading, /Verifying demo backend mode/);
  const denied = renderAuth(React.createElement(DemoLogin), null, { isAuthenticated: false, stage: 'login', message: 'Fictional rejection' });
  assert.match(denied, /Fictional rejection/);
  assert.match(denied, /Fictional account email/);
  assert(!denied.includes('Authenticator code'));
});

test('normal controller still refuses password-only session responses', async () => {
  const auth = new AuthController({ login: async () => ({ ...csrf, authenticated: true }) });
  await auth.login('fictional', 'fictional');
  assert.equal(auth.snapshot().user, null);
  assert.notEqual(auth.snapshot().stage, 'authenticated');
});

test('demo source never persists credentials or invokes MFA endpoints', () => {
  for (const file of ['api.ts', 'controller.ts', 'Provider.tsx', 'DemoLogin.tsx', 'main.tsx']) {
    const source = read('../src/demo/' + file);
    assert.doesNotMatch(source, /localStorage|sessionStorage|\/auth\/mfa|\/auth\/recovery/);
  }
});
