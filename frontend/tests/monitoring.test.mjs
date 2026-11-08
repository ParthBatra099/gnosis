import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router-dom';
import { AxiosError } from 'axios';
import { apiClient, setCsrfToken } from '../src/api/client.ts';
import { MonitoringController, initialFilters, filterQuery } from '../src/pages/admin/monitoringController.ts';
import { MonitoringView, ActivityList } from '../src/pages/admin/MonitoringPage.tsx';
import { AuthContext } from '../src/context/AuthContext.ts';
import { ProtectedRoute } from '../src/routes/ProtectedRoute.tsx';
import { Sidebar } from '../src/components/layout/Sidebar.tsx';
import { MonitoringPage } from '../src/pages/admin/MonitoringPage.tsx';

const time = '2026-11-08T12:00:00Z';
const risk = { id: 'risk', actor_id: 'employee-fixture', scope: 'EMPLOYEE', scope_key: 'employee-fixture', score: 55, level: 'HIGH', policy_version: 'gnosis-observe-v1', timestamp: time, window_start: time, window_end: time, factors: [{ factor: 'denials', active: true, contribution: 15, explanation: 'Three recorded denied attempts.' }], evidence: { audit_ids: ['a'], disclosure_ids: [], metrics: { denials: 3 } } };
const detection = { id: 'detection', event_type: 'REPEATED_DENIED_ACCESS', severity: 'HIGH', actor_id: 'employee-fixture', resource_id: 'resource-fixture', timestamp: time, description: 'Recorded denied attempts.', evidence: { rule: 'REPEATED_DENIED_ACCESS', threshold: 3, session_ref: 'a'.repeat(64) }, related_incidents: [{ id: 'incident', status: 'OPEN' }] };
const activity = { id: 'disclosure:record', source: 'disclosure', source_id: 'record', timestamp: time, category: 'DATA_DISCLOSED', actor_id: 'employee-fixture', resource_id: 'resource-fixture', department_ids: ['assigned-dept'], severity: null, outcome: 'APPLICATION_COMPLETE', explanation: 'Application prepared business record.', sensitivity: 'INTERNAL', record_id: 'fictional-record', session_ref: null, incident_id: null, related_incidents: [], transport_state: 'UNKNOWN', status: null };
const incident = { id: 'incident', title: 'Synthetic investigation', description: 'Review recorded events.', severity: 'HIGH', status: 'OPEN', created_at: time, updated_at: time, reporter_id: 'employee-fixture', assigned_to_id: 'admin-fixture', resource_id: 'resource-fixture', resolution_notes: null, history: [{ id: 'history', timestamp: time, actor_id: 'admin-fixture', action: 'INCIDENT_CREATED', status: null }], detection_evidence: [detection] };
const overview = { start: time, end: time, detections: 17, high_detections: 11, critical_detections: 2, elevated_employees: 4, open_incidents: 3, investigating_incidents: 2, resolved_incidents: 1, closed_incidents: 0, disclosure_events: 123, distinct_records: 70, recent_detections: [detection], employee_risks: [risk], recent_activity: [activity] };
const page = (items, total = items.length, offset = 0) => ({ items, total, offset, limit: 20 });
const denyNetwork = async () => { throw new Error('No external service permitted in tests'); };
apiClient.defaults.adapter = denyNetwork;
afterEach(() => { setCsrfToken(null); apiClient.defaults.adapter = denyNetwork; });
function transport(handler) {
  const requests = [];
  apiClient.defaults.adapter = async config => {
    requests.push(config);
    const result = config.url === '/auth/csrf' ? { data: { csrf_token: 'synthetic-csrf' } } : await handler(config);
    if (result.status >= 400) throw new AxiosError('Fixture denial', 'ERR_BAD_REQUEST', config, null, { status: result.status, data: {}, config });
    return { status: result.status || 200, data: result.data, config };
  };
  return requests;
}
const render = child => renderToStaticMarkup(React.createElement(MemoryRouter, null, child));
const view = controller => render(React.createElement(MonitoringView, { controller, state: controller.snapshot() }));

test('dashboard renders persisted API figures and evidence, without demo fallbacks', async () => {
  const requests = transport(() => ({ data: overview }));
  const controller = new MonitoringController('dashboard');
  await controller.load();
  const html = view(controller);
  assert.equal(requests[0].url, '/console/dashboard/security-overview');
  for (const text of ['123', '70', '17', 'gnosis-observe-v1', 'Three recorded denied attempts.', 'network delivery and user receipt remain unknown']) assert.ok(html.includes(text));
  assert.doesNotMatch(html, /Prapti Singhal|System protected|sample data|12\.4%/);
});

test('dashboard handles zero persisted values and empty evidence lists', async () => {
  transport(() => ({ data: { ...overview, detections: 0, employee_risks: [], recent_detections: [], recent_activity: [] } }));
  const controller = new MonitoringController('dashboard');
  await controller.load();
  const html = view(controller);
  assert.match(html, /No recorded employee assessments/);
  assert.match(html, /No visible detections/);
  assert.match(html, /No matching security activity/);
});

test('loading, error and empty states do not retain previous privileged rows', async () => {
  const controller = new MonitoringController('detections');
  let resolve;
  transport(() => new Promise(done => { resolve = done; }));
  const pending = controller.load();
  await new Promise(done => setImmediate(done));
  assert.match(view(controller), /Loading authorized security evidence/);
  resolve({ data: page([]) });
  await pending;
  assert.match(view(controller), /No matching evidence/);
  transport(() => ({ status: 403 }));
  await controller.load();
  assert.equal(controller.snapshot().page, null);
  assert.match(view(controller), /current authorized scope/);
});

test('event filters, incident status and timezone-qualified ranges reach the backend', async () => {
  const requests = transport(config => ({ data: config.url.includes('/risk/employees/') ? { ...page([risk]), latest: risk } : page([detection]) }));
  const controller = new MonitoringController('detections');
  await controller.load({ ...initialFilters, severity: 'HIGH', event_type: 'REPEATED_DENIED_ACCESS', employee_id: 'employee-fixture', status: 'OPEN', start: time, end: '2026-11-09T12:00:00Z' });
  const params = requests[0].params;
  assert.equal(params.severity, 'HIGH');
  assert.equal(params.incident_status, 'OPEN');
  assert.equal(params.status, undefined);
  assert.equal(params.start, '2026-11-08T12:00:00.000Z');
  assert.match(view(controller), /Latest visible employee risk/);
  assert.match(view(controller), /Incident incident/);
});

test('timeline category, session and pagination filters use bounded backend queries', async () => {
  const requests = transport(() => ({ data: page([activity], 45, 20) }));
  const controller = new MonitoringController('timeline');
  await controller.load({ ...initialFilters, category: 'DATA_DISCLOSED', session_ref: 'a'.repeat(64) }, 20);
  assert.equal(requests[0].url, '/monitoring/timeline');
  assert.equal(requests[0].params.limit, 20);
  assert.equal(requests[0].params.offset, 20);
  assert.equal(requests[0].params.category, 'DATA_DISCLOSED');
  assert.match(view(controller), /Showing 21/);
  assert.match(view(controller), /user receipt is not established/);
});

test('allowed attempts, denied attempts and prepared disclosures remain visibly distinct', () => {
  const html = render(React.createElement(ActivityList, { items: [activity, { ...activity, id: 'audit:a', category: 'ACCESS_ALLOWED', source: 'audit', transport_state: null }, { ...activity, id: 'audit:b', category: 'ACCESS_DENIED', source: 'audit', transport_state: null }] }));
  assert.match(html, /Authorization allowed the attempt/);
  assert.match(html, /zero exposure from this request/);
  assert.match(html, /transport UNKNOWN/);
});

test('incident detail and confirmed status update use existing CSRF-protected PATCH then refresh', async () => {
  let current = incident;
  const requests = transport(config => {
    if (config.method === 'patch') { assert.equal(config.headers.get('X-CSRF-Token'), 'synthetic-csrf'); current = { ...incident, status: 'INVESTIGATING', updated_at: '2026-11-08T12:01:00Z' }; return { data: current }; }
    if (config.url === '/console/incidents/page') return { data: page([current]) };
    return { data: current };
  });
  const controller = new MonitoringController('incidents');
  await controller.load();
  await controller.openIncident('incident');
  assert.match(view(controller), /Recorded incident history/);
  await controller.updateIncident('INVESTIGATING', 'Reviewed fixture', false);
  assert.equal(requests.some(r => r.method === 'patch'), false);
  await controller.updateIncident('INVESTIGATING', 'Reviewed fixture', true);
  assert.equal(requests.filter(r => r.method === 'patch').length, 1);
  assert.equal(controller.snapshot().detail.status, 'INVESTIGATING');
  assert.match(view(controller), /Incident updated from the backend/);
});

test('resolution requires notes and unsupported transitions are not submitted', async () => {
  const requests = transport(() => ({ data: { ...incident, status: 'INVESTIGATING' } }));
  const controller = new MonitoringController('incidents');
  await controller.openIncident('incident');
  await controller.updateIncident('RESOLVED', '', true);
  assert.match(controller.snapshot().error, /notes are required/);
  await controller.updateIncident('CLOSED', 'Reviewed', true);
  assert.equal(requests.some(r => r.method === 'patch'), false);
});

test('late reads cannot repopulate evidence after persisted session rejection', async () => {
  const controller = new MonitoringController('dashboard');
  const disconnect = controller.connect();
  let resolve;
  transport(config => config.url === '/console/dashboard/security-overview' ? new Promise(done => { resolve = done; }) : { status: 401 });
  const pending = controller.load();
  await new Promise(done => setImmediate(done));
  await assert.rejects(apiClient.get('/auth/me'));
  resolve({ data: overview }); await pending;
  assert.equal(controller.snapshot().overview, null);
  assert.match(controller.snapshot().error, /Session expired/);
  disconnect();
});

test('rejected mutation clears detail and is never automatically replayed', async () => {
  let posts = 0;
  transport(config => { if (config.method === 'patch') { posts++; return { status: 403 }; } return { data: incident }; });
  const controller = new MonitoringController('incidents');
  await controller.openIncident('incident');
  await controller.updateIncident('INVESTIGATING', 'Reviewed', true);
  assert.equal(posts, 1);
  assert.equal(controller.snapshot().detail, null);
});

test('accepted mutation with unavailable refresh reports the accepted write separately', async () => {
  let updated = false;
  transport(config => {
    if (config.method === 'patch') { updated = true; return { data: incident }; }
    return updated ? { status: 403 } : { data: incident };
  });
  const controller = new MonitoringController('incidents');
  await controller.openIncident('incident');
  await controller.updateIncident('INVESTIGATING', 'Reviewed', true);
  assert.match(controller.snapshot().error, /update was accepted/);
  assert.equal(controller.snapshot().detail, null);
});

for (const role of ['SUPER_ADMIN', 'DEPARTMENT_ADMIN', 'EMPLOYEE', null, 'ADMIN']) {
  test(`canonical ${role} monitoring navigation and guard`, () => {
    const user = { id: 'actor', organization_role: role, role: 'ADMIN' };
    const admin = role === 'SUPER_ADMIN' || role === 'DEPARTMENT_ADMIN';
    const provider = child => React.createElement(AuthContext.Provider, { value: { user, isAuthenticated: true, isLoading: false, logout: async () => {} } }, child);
    const nav = render(provider(React.createElement(Sidebar, { mobileOpen: false, onCloseMobile: () => {} })));
    assert.equal(nav.includes('href="/admin/timeline"'), admin);
    const guarded = render(provider(React.createElement(ProtectedRoute, { allowedRoles: ['SUPER_ADMIN', 'DEPARTMENT_ADMIN'] }, 'SECURITY-MONITOR-FIXTURE')));
    assert.equal(guarded.includes('SECURITY-MONITOR-FIXTURE'), admin);
    if (!admin) assert.match(render(provider(React.createElement(MonitoringPage, { mode: 'dashboard' }))), /Administrative monitoring unavailable/);
  });
}

test('invalid/reversed dates fail before any API call', () => {
  assert.throws(() => filterQuery({ ...initialFilters, start: 'bad date' }), /valid dates/);
  assert.throws(() => filterQuery({ ...initialFilters, start: '2026-11-09T00:00:00Z', end: '2026-11-08T00:00:00Z' }), /precede/);
});
