import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { AxiosError } from 'axios';
import { apiClient, enableLocalDemoTransport, setCsrfToken, DEMO_AUTH_MODE } from '../src/api/client.ts';
import { getBusinessRecords } from '../src/api/resources.ts';
import { BusinessRecordsController, connectBusinessRecords } from '../src/pages/employee/businessRecordsController.ts';
import { BusinessRecordsView } from '../src/pages/employee/BusinessRecords.tsx';
import { AuthController } from '../src/context/authController.ts';
import { DemoController } from '../src/demo/controller.ts';

const resources = [
  { id: 'fictional-a', name: 'Fictional HR records', department_id: 'fictional-hr', sensitivity: 'INTERNAL' },
  { id: 'fictional-b', name: 'Fictional Sales records', department_id: 'fictional-sales', sensitivity: 'CONFIDENTIAL' },
];
const record = id => ({ id, category: 'SYNTHETIC_BUDGET', sensitivity: 'INTERNAL', values: { fictional: '<script>not executable</script>', units: 7 } });
const page = (resource = 'fictional-a', records = [record('fictional-record')]) => ({ response_id: 'fictional-response',
  resource_id: resource, records, disclosure_semantics: 'APPLICATION_COMPLETE; network delivery UNKNOWN' });
const failure = status => Object.assign(new Error('Fictional denial'), { response: { status } });
const make = overrides => new BusinessRecordsController({ metadata: async () => resources, records: async id => page(id), ...overrides });
const render = controller => renderToStaticMarkup(React.createElement(BusinessRecordsView, { controller, state: controller.snapshot() }));
const rejectNetwork = async () => { throw new Error('Tests must never contact a real service'); };
apiClient.defaults.adapter = rejectNetwork;
afterEach(() => { setCsrfToken(null); apiClient.defaults.adapter = rejectNetwork; });
function adapter(handler) {
  apiClient.defaults.adapter = async config => {
    const [status, data] = handler(config);
    const response = { config, status, data, statusText: String(status), headers: {} };
    if (status >= 400) throw new AxiosError('Fictional response', undefined, config, undefined, response);
    return response;
  };
}

test('mount lifecycle loads metadata only; selection, page size and focus never retrieve records', async () => {
  let metadataCalls = 0, recordCalls = 0;
  const controller = make({ metadata: async () => { metadataCalls++; return resources; },
    records: async id => { recordCalls++; return page(id); } });
  const previousWindow = Object.getOwnPropertyDescriptor(globalThis, 'window');
  Object.defineProperty(globalThis, 'window', { value: new EventTarget(), configurable: true });
  const stop = connectBusinessRecords(controller);
  try {
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(metadataCalls, 1);
    controller.select('fictional-a'); controller.setLimit(10);
    globalThis.window.dispatchEvent(new Event('focus'));
    assert.equal(recordCalls, 0);
    assert.equal(controller.snapshot().response, null);
    const component = readFileSync(new URL('../src/pages/employee/BusinessRecords.tsx', import.meta.url), 'utf8');
    assert.match(component, /useEffect\(\(\) => connectBusinessRecords\(controller\)/);
    assert.doesNotMatch(component, /addEventListener|setInterval|setTimeout|prefetch/);
    await controller.request();
    assert.equal(recordCalls, 1);
  } finally {
    stop();
    if (previousWindow) Object.defineProperty(globalThis, 'window', previousWindow);
    else delete globalThis.window;
  }
});

test('metadata failure clears records and does not manufacture permissions or data', async () => {
  let fail = false;
  const controller = make({ metadata: async () => { if (fail) throw failure(503); return resources; } });
  await controller.loadMetadata(); controller.select('fictional-a'); await controller.request();
  fail = true; await controller.loadMetadata();
  assert.equal(controller.snapshot().response, null);
  assert.deepEqual(controller.snapshot().resources, []);
  assert.match(render(controller), /metadata is unavailable/);
});

test('explicit success renders real response fields, escaped values and disclosure limitations', async () => {
  const controller = make();
  await controller.loadMetadata(); controller.select('fictional-a'); await controller.request();
  const html = render(controller);
  for (const text of ['Fictional HR records', 'INTERNAL', 'SYNTHETIC_BUDGET', 'fictional-record', 'fictional-response',
    'APPLICATION_COMPLETE; network delivery UNKNOWN', 'does not prove network delivery', 'Offset 0', 'Page size 25']) assert(html.includes(text));
  assert(html.includes('&lt;script&gt;'));
  assert(!html.includes('<script>'));
  assert(!html.includes('Total records'));
  assert.equal(controller.snapshot().outcome, 'allowed');
});

test('pagination passes exact limit/offset and treats empty pages without an invented total', async () => {
  const calls = [];
  const controller = make({ records: async (id, limit, offset) => { calls.push([id, limit, offset]);
    return page(id, offset === 0 ? [record('one'), record('two')] : []); } });
  await controller.loadMetadata(); controller.select('fictional-a'); controller.setLimit(2);
  assert.equal(calls.length, 0);
  await controller.request(); await controller.request(2);
  assert.deepEqual(calls, [['fictional-a', 2, 0], ['fictional-a', 2, 2]]);
  assert.match(render(controller), /No records returned for this page/);
  assert.match(render(controller), /next page may be empty/);
  assert(!Object.hasOwn(controller.snapshot().response, 'total'));
  await controller.request(0);
  assert.equal(controller.snapshot().response.records.length, 2);
});

for (const status of [401, 403, 404, 422, 503, 500]) test(`record failure ${status} clears earlier data and does not claim disclosure success`, async () => {
  let deny = false;
  const controller = make({ records: async id => { if (deny) throw failure(status); return page(id); } });
  await controller.loadMetadata(); controller.select('fictional-a'); await controller.request();
  deny = true; await controller.request();
  assert.equal(controller.snapshot().response, null);
  const html = render(controller);
  assert(!html.includes('fictional-record'));
  assert(!html.includes('Access allowed — records response received'));
  assert(html.includes('role="alert"'));
  assert.equal(controller.snapshot().outcome, status === 401 ? 'session-ended' : status === 403 ? 'denied' : 'error');
  if (status === 403) assert.match(html, /Access denied by backend security policy/);
});

test('changing resource or page size clears data without requesting another page', async () => {
  let calls = 0;
  const controller = make({ records: async id => { calls++; return page(id); } });
  await controller.loadMetadata(); controller.select('fictional-a'); await controller.request();
  controller.select('fictional-b');
  assert.equal(controller.snapshot().response, null); assert.equal(calls, 1);
  await controller.request(); controller.setLimit(50);
  assert.equal(controller.snapshot().response, null); assert.equal(calls, 2);
});

test('late response and failure from the previous selection cannot overwrite current records', async () => {
  for (const fail of [false, true]) {
    let finish, deny;
    const controller = make({ records: id => id === 'fictional-a' ? new Promise((resolve, reject) => { finish = resolve; deny = reject; }) : Promise.resolve(page(id)) });
    await controller.loadMetadata(); controller.select('fictional-a');
    const old = controller.request();
    controller.select('fictional-b'); await controller.request();
    if (fail) deny(failure(403)); else finish(page('fictional-a'));
    await old;
    assert.equal(controller.snapshot().selectedId, 'fictional-b');
    assert.equal(controller.snapshot().response.resource_id, 'fictional-b');
    assert.equal(controller.snapshot().error, '');
  }
});

test('duplicate clicks do not submit duplicate requests, and disconnect discards late responses', async () => {
  let finish, calls = 0;
  const controller = make({ records: () => { calls++; return new Promise(resolve => { finish = resolve; }); } });
  const stop = controller.connect();
  await controller.loadMetadata(); controller.select('fictional-a');
  const pending = controller.request(); await controller.request();
  assert.equal(calls, 1);
  stop(); finish(page()); await pending;
  assert.equal(controller.snapshot().response, null);
});

test('protected session rejection clears record state and blocks late-response resurrection', async () => {
  let finish;
  const controller = make({ records: () => new Promise(resolve => { finish = resolve; }) });
  const stop = controller.connect();
  try {
    await controller.loadMetadata(); controller.select('fictional-a');
    const pending = controller.request();
    adapter(() => [401, { detail: 'Fictional revoked session' }]);
    await assert.rejects(apiClient.get('/auth/me'));
    finish(page()); await pending;
    assert.equal(controller.snapshot().response, null);
    assert.equal(controller.snapshot().outcome, 'session-ended');
    assert.equal(controller.snapshot().selectedId, '');
  } finally { stop(); }
});

test('invalid pagination fails before any network request', async () => {
  for (const [limit, offset] of [[0, 0], [101, 0], [25, -1], [25, 0.5], [NaN, 0]])
    await assert.rejects(getBusinessRecords('fictional-a', limit, offset));
});

test('malformed or cross-resource response is never displayed', async () => {
  for (const body of [page('wrong-resource'), { ...page(), records: null }, { ...page(), records: [{ ...record('one'), values: null }] }]) {
    adapter(() => [200, body]);
    await assert.rejects(getBusinessRecords('fictional-a'));
  }
});

test('normal MFA and demo identities use the same cookie-authenticated record API without permission inference', async () => {
  const actor = { id: 'fictional-person', name: 'Fictional', email: 'demo-fictional@example.com', role: 'ADMIN', organization_role: 'EMPLOYEE', department_id: 'fictional-hr', active: true };
  const calls = [];
  adapter(config => {
    calls.push(config);
    if (config.url === '/health') return [200, { auth_mode: DEMO_AUTH_MODE, demo_mode: true }];
    if (config.url === '/auth/csrf') return [200, { csrf_token: 'fictional-csrf', auth_mode: DEMO_AUTH_MODE }];
    if (config.url === '/auth/login') return [200, { next_step: 'MFA_VERIFICATION', challenge_id: 'fictional', challenge_secret: 'fictional-restricted-capability' }];
    if (config.url === '/auth/mfa/verify') return [200, { authenticated: true, csrf_token: 'fictional-csrf' }];
    if (config.url === '/auth/me') return [200, actor];
    if (config.url === '/access/resources/metadata') return [200, resources];
    if (config.url === '/resources/fictional-a/records') return [200, page()];
    throw new Error('Unexpected endpoint');
  });
  const normal = new AuthController();
  await normal.login(actor.email, 'Fictional-password');
  assert.equal(normal.snapshot().stage, 'mfa');
  await normal.verify('123456');
  assert.equal(normal.snapshot().stage, 'authenticated');
  const normalRecords = new BusinessRecordsController();
  await normalRecords.loadMetadata(); normalRecords.select('fictional-a'); await normalRecords.request();
  enableLocalDemoTransport('https://localhost:8443');
  const demo = new DemoController(); await demo.restore();
  assert.equal(demo.snapshot().stage, 'authenticated');
  const demoRecords = new BusinessRecordsController();
  await demoRecords.loadMetadata(); demoRecords.select('fictional-a'); await demoRecords.request();
  const reads = calls.filter(config => config.url.endsWith('/records'));
  assert.equal(reads.length, 2);
  assert(reads.every(config => config.withCredentials === true && config.headers.get('Authorization') === undefined));
  assert(reads.every(config => config.params.limit === 25 && config.params.offset === 0));
  assert.equal(normalRecords.snapshot().response.response_id, demoRecords.snapshot().response.response_id);
});

test('new browser source has no storage, retry, focus or frontend monitoring generation', () => {
  for (const path of ['../src/pages/employee/BusinessRecords.tsx', '../src/pages/employee/businessRecordsController.ts']) {
    const source = readFileSync(new URL(path, import.meta.url), 'utf8');
    assert.doesNotMatch(source, /localStorage|sessionStorage|setInterval|setTimeout|addEventListener|\/monitoring\//);
  }
});
