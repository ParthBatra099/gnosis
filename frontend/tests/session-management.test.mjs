import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { AxiosError } from 'axios';
import { apiClient, setCsrfToken } from '../src/api/client.ts';
import { SessionController } from '../src/pages/auth/sessionController.ts';
import { AuthController } from '../src/context/authController.ts';
import { sessionApi } from '../src/api/sessions.ts';

const session = { session_ref: 'a'.repeat(64), created_at: '2026-01-01', last_activity_at: '2026-01-01', expires_at: '2026-12-01', state: 'ACTIVE', is_current: false };
const page = { items: [session], total: 1, limit: 20, offset: 0 };
const denyNetwork = async () => { throw new Error('No real network is permitted by this test'); };
apiClient.defaults.adapter = denyNetwork;
afterEach(() => { setCsrfToken(null); apiClient.defaults.adapter = denyNetwork; });
function mock(handler) {
  const calls = [];
  apiClient.defaults.adapter = async config => {
    calls.push(config);
    if (config.url === '/auth/csrf') return { status: 200, data: { csrf_token: 'fixture-csrf' }, config };
    const result = await handler(config);
    if (result.status >= 400) throw new AxiosError('Denied', 'ERR_BAD_REQUEST', config, null, { ...result, config });
    return { status: 200, ...result, config };
  };
  return calls;
}

test('own sessions use cookie transport and confirmation with an audited reason', async () => {
  const calls = mock(config => ({ status: config.method === 'post' ? 204 : 200, data: page }));
  const controller = new SessionController();
  await controller.load();
  controller.requestRevoke(session);
  assert.equal(calls.filter(call => call.method === 'post').length, 0);
  await controller.confirm(' Reviewed sign-out ');
  const request = calls.find(call => call.method === 'post');
  assert.equal(request.url, '/auth/sessions/' + session.session_ref + '/revoke');
  assert.equal(request.withCredentials, true);
  assert.equal(request.headers.get('X-CSRF-Token'), 'fixture-csrf');
  assert.equal(request.headers.has('Authorization'), false);
  assert.deepEqual(JSON.parse(request.data), { reason: 'Reviewed sign-out' });
  assert.match(controller.snapshot().message, /backend confirmed/);
});
test('cross-user API uses only the Super Admin organization endpoint; failure is authoritative', async () => {
  const calls = mock(() => ({ status: 403, data: {} }));
  const controller = new SessionController('fictional-user');
  await controller.load();
  assert.equal(calls[0].url, '/organization/employees/fictional-user/sessions');
  assert.equal(controller.snapshot().page, null);
  assert.match(controller.snapshot().error, /denied/);
  assert.equal(controller.snapshot().message, null);
});
test('cancelling session confirmation makes no write and blank reasons cannot revoke', async () => {
  const calls = mock(() => ({ data: page }));
  const controller = new SessionController();
  await controller.load(); controller.requestRevoke(session);
  await controller.confirm(' ');
  assert.match(controller.snapshot().error, /reason/);
  controller.cancel(); await controller.confirm('Reviewed');
  assert.equal(calls.some(call => call.method === 'post'), false);
});
test('expired or revoked session request clears session inventory through existing rejection flow', async () => {
  let denied = false;
  mock(() => denied ? { status: 401, data: {} } : { data: page });
  const controller = new SessionController(); const disconnect = controller.connect();
  await controller.load(); denied = true; await controller.load();
  assert.equal(controller.snapshot().page, null);
  assert.match(controller.snapshot().error, /session ended/);
  disconnect();
});
test('targeted revocation failure cannot claim success or retain stale session data', async () => {
  mock(config => config.method === 'post' ? { status: 503, data: {} } : { data: page });
  const controller = new SessionController();
  await controller.load(); controller.requestRevoke(session); await controller.confirm('Reviewed');
  assert.equal(controller.snapshot().message, null);
  assert.equal(controller.snapshot().page, null);
  assert.match(controller.snapshot().error, /may already have committed/);
});
test('a second confirmation cannot submit a duplicate revocation while the first is pending', async () => {
  let finish, writes = 0;
  mock(async config => {
    if (config.method === 'post') { writes++; await new Promise(resolve => { finish = resolve; }); return { status: 204 }; }
    return { data: page };
  });
  const controller = new SessionController(); await controller.load(); controller.requestRevoke(session);
  const first = controller.confirm('Reviewed');
  await new Promise(resolve => setImmediate(resolve));
  await controller.confirm('Reviewed again');
  assert.equal(writes, 1);
  finish(); await first;
});
test('session list pagination uses bounded contract fields', async () => {
  const calls = mock(() => ({ data: page }));
  await sessionApi.list(undefined, 20);
  assert.deepEqual(calls[0].params, { limit: 20, offset: 20 });
  const controller = new SessionController(); await controller.load(100001);
  assert.equal(calls.length, 1);
});
test('one-time recovery codes survive temporary profile failure without granting workspace access', async () => {
  const controller = new AuthController({
    login: async () => ({ next_step: 'MFA_ENROLLMENT', challenge_id: 'fixture', challenge_secret: 'fixture-only-secret' }),
    enroll: async () => ({ next_step: 'VERIFY_ENROLLMENT', provisioning_uri: 'otpauth://totp/Fixture?secret=FICTIONAL', qr_payload: 'otpauth://totp/Fixture?secret=FICTIONAL' }),
    verify: async () => ({ authenticated: true, csrf_token: 'fixture-csrf', recovery_codes: ['fictional-one-time-code'] }),
    profile: async () => { throw Object.assign(new Error('temporary'), { response: { status: 503 } }); },
  });
  await controller.login('fixture', 'password'); await controller.startEnrollment(); await controller.verify('123456');
  assert.equal(controller.snapshot().stage, 'recovery-codes');
  assert.equal(controller.snapshot().user, null);
  assert.deepEqual(controller.snapshot().recoveryCodes, ['fictional-one-time-code']);
  assert.equal(controller.snapshot().provisioningUri, null);
  controller.finishRecoveryCodes();
  assert.deepEqual(controller.snapshot().recoveryCodes, []);
  assert.equal(controller.snapshot().stage, 'login');
});
test('a real protected 401 clears issued recovery codes instead of preserving rejected authentication', async () => {
  mock(config => ({ status: config.url === '/auth/me' ? 401 : 200, data: config.url === '/auth/login' ?
    { next_step: 'MFA_VERIFICATION', challenge_id: 'fixture', challenge_secret: 'fixture-only-secret' } :
    { authenticated: true, csrf_token: 'new-csrf', recovery_codes: ['fictional-once-only'] } }));
  const controller = new AuthController(); const disconnect = controller.connect();
  await controller.login('fixture@example.invalid', 'password'); await controller.verify('123456');
  assert.equal(controller.snapshot().stage, 'session-ended');
  assert.deepEqual(controller.snapshot().recoveryCodes, []);
  assert.equal(controller.snapshot().user, null);
  disconnect();
});
test('recovery acknowledgement waits for the pending profile attempt and cannot redisplay saved codes', async () => {
  let finishProfile;
  const controller = new AuthController({
    login: async () => ({ next_step: 'MFA_VERIFICATION', challenge_id: 'fixture', challenge_secret: 'fixture-only' }),
    verify: async () => ({ authenticated: true, csrf_token: 'fixture-csrf', recovery_codes: ['fictional-code'] }),
    profile: () => new Promise(resolve => { finishProfile = resolve; }),
  });
  await controller.login('fixture', 'password');
  const pending = controller.verify('123456');
  await new Promise(resolve => setImmediate(resolve));
  controller.finishRecoveryCodes();
  assert.equal(controller.snapshot().stage, 'recovery-codes');
  assert.equal(controller.snapshot().busy, true);
  finishProfile({ id: 'fixture', organization_role: 'EMPLOYEE' });
  await pending; controller.finishRecoveryCodes();
  assert.equal(controller.snapshot().stage, 'authenticated');
  assert.deepEqual(controller.snapshot().recoveryCodes, []);
});
test('controlled login copy contains no replacement glyphs and dashboard uses the monitoring integration', () => {
  const login = readFileSync(new URL('../src/pages/auth/Login.tsx', import.meta.url), 'utf8');
  assert.doesNotMatch(login, /\ufffd/);
  assert.match(readFileSync(new URL('../src/pages/admin/AdminDashboard.tsx', import.meta.url), 'utf8'), /MonitoringPage mode="dashboard"/);
});
