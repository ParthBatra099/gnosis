import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router-dom';
import { AxiosError } from 'axios';
import { apiClient, setCsrfToken } from '../src/api/client.ts';
import { organizationApi } from '../src/api/organization.ts';
import { OrganizationController, prepareCommand, organizationError } from '../src/pages/admin/organizationController.ts';
import { OrganizationView, MutationForm } from '../src/pages/admin/OrganizationPage.tsx';
import { AuthController } from '../src/context/authController.ts';
import { AuthContext } from '../src/context/AuthContext.ts';
import { Sidebar } from '../src/components/layout/Sidebar.tsx';
import { ProtectedRoute } from '../src/routes/ProtectedRoute.tsx';

const revision = 'a'.repeat(64), newer = 'b'.repeat(64);
const actor = role => ({ id: 'fictional-operator', name: 'Operator fixture', email: 'operator@example.invalid', role: 'ADMIN', organization_role: role, department_id: 'home-is-not-authority', active: true });
const department = { id: 'fictional-dept', name: 'Fixture department', description: 'Fixture description', active: true, revision };
const employee = { id: 'fictional-person', name: 'Fixture person', email: 'person@example.invalid', organization_role: 'DEPARTMENT_ADMIN', home_department_id: 'home-membership-only', active: true, revision };
const assignment = { id: 'fictional-assignment', user_id: employee.id, department_id: 'explicit-admin-department', assigned_at: '2026-01-01T00:00:00Z', assigned_by: 'fictional-reviewer', revoked_at: null, revoked_by: null, revision };
const revoked = { ...assignment, id: 'fictional-revoked', revoked_at: '2026-01-02T00:00:00Z', revoked_by: 'fictional-reviewer' };
const page = (items, offset = 0, total = items.length, limit = 20) => ({ items, total, offset, limit });
const filters = { q: '', active: '', limit: 20, offset: 0, home_department_id: '', department_id: '', user_id: '' };
const rejectNetwork = async () => { throw new Error('Tests must never contact a real service'); };
apiClient.defaults.adapter = rejectNetwork;
afterEach(() => { setCsrfToken(null); apiClient.defaults.adapter = rejectNetwork; });
function transport(handler) {
  const requests = [];
  apiClient.defaults.adapter = async config => {
    requests.push(config);
    if (config.url === '/auth/csrf') return { status: 200, data: { csrf_token: 'test-csrf' }, config };
    const result = await handler(config);
    const status = result?.status || 200;
    if (status >= 400) throw new AxiosError('Fictional denial', 'ERR_BAD_REQUEST', config, null, { status, data: { detail: { code: result.code } }, config });
    return { status, data: result?.data, config };
  };
  return requests;
}
function baseResponse(config) {
  if (config.url.endsWith('/assignments')) return { data: page([assignment, revoked]) };
  if (config.url === '/organization/departments') return { data: page([department]) };
  if (config.url === '/organization/employees') return { data: page([employee]) };
  if (config.url === '/organization/departments/' + department.id) return { data: department };
  if (config.url === '/organization/employees/' + employee.id) return { data: employee };
  throw new Error('Unexpected mocked request: ' + config.url);
}
const view = (controller, patch = {}) => renderToStaticMarkup(React.createElement(MemoryRouter, null, React.createElement(OrganizationView, { controller, state: { ...controller.snapshot(), ...patch } })));
function sidebar(user) {
  return renderToStaticMarkup(React.createElement(MemoryRouter, null, React.createElement(AuthContext.Provider, { value: { user, logout: async () => {} } }, React.createElement(Sidebar, { mobileOpen: false }))));
}

test('Super Admin navigation enables supported organization screens', () => {
  const markup = sidebar(actor('SUPER_ADMIN'));
  for (const path of ['/admin/departments', '/admin/employees', '/admin/assignments']) assert.match(markup, new RegExp('href="' + path + '"'));
});
test('Department Admin navigation has scoped reads and retains employee links, without assignment management', () => {
  const markup = sidebar(actor('DEPARTMENT_ADMIN'));
  assert.match(markup, /Assigned departments/);
  assert.match(markup, /Department employees/);
  assert.match(markup, /href="\/employee"/);
  assert.doesNotMatch(markup, /href="\/admin\/assignments"|Organization identities/);
});
for (const role of ['EMPLOYEE', null, undefined, 'ADMIN', 'super_admin']) {
  test(`canonical ${String(role)} has no organization management navigation, despite legacy ADMIN`, () => {
    const current = actor(role);
    assert.doesNotMatch(sidebar(current), /href="\/admin/);
    const controller = new OrganizationController('employees', current);
    controller.begin('employee-create');
    assert.equal(controller.snapshot().editor, null);
    assert.doesNotMatch(view(controller), /Create employee identity/);
  });
}
test('assignment route presentation is Super Admin only', () => {
  for (const role of ['SUPER_ADMIN', 'DEPARTMENT_ADMIN', 'EMPLOYEE', null]) {
    const child = React.createElement(ProtectedRoute, { allowedRoles: ['SUPER_ADMIN'] }, 'assignment-controls-fixture');
    const html = renderToStaticMarkup(React.createElement(MemoryRouter, null, React.createElement(AuthContext.Provider, { value: { user: actor(role), isAuthenticated: true, isLoading: false } }, child)));
    assert.equal(html.includes('assignment-controls-fixture'), role === 'SUPER_ADMIN');
  }
});

const mutations = [
  ['department-create', null, { name: 'New department', description: '', reason: 'Explicit review' }, '/organization/departments', 'post', { name: 'New department', description: null, reason: 'Explicit review' }],
  ['department-update', department, { name: department.name, description: '', reason: 'Clear description' }, '/organization/departments/' + department.id, 'patch', { expected_revision: revision, description: null, reason: 'Clear description' }],
  ['department-deactivate', department, { reason: 'Soft deactivate' }, '/organization/departments/' + department.id + '/deactivate', 'post', { expected_revision: revision, reason: 'Soft deactivate' }],
  ['department-reactivate', { ...department, active: false }, { reason: 'Reactivate' }, '/organization/departments/' + department.id + '/reactivate', 'post', { expected_revision: revision, reason: 'Reactivate' }],
  ['employee-create', null, { name: 'New person', email: 'new@example.invalid', home_department_id: department.id, reason: 'Create inactive identity', password: 'must-be-excluded', active: 'true', organization_role: 'SUPER_ADMIN' }, '/organization/employees', 'post', { name: 'New person', email: 'new@example.invalid', home_department_id: department.id, reason: 'Create inactive identity' }],
  ['employee-update', employee, { name: 'Updated name', email: employee.email, home_department_id: employee.home_department_id, reason: 'Reviewed profile' }, '/organization/employees/' + employee.id, 'patch', { expected_revision: revision, name: 'Updated name', reason: 'Reviewed profile' }],
  ['employee-role', employee, { organization_role: 'EMPLOYEE', reason: 'Reviewed role after revocation' }, '/organization/employees/' + employee.id + '/role', 'post', { expected_revision: revision, organization_role: 'EMPLOYEE', reason: 'Reviewed role after revocation' }],
  ['employee-deactivate', employee, { reason: 'Deactivate account' }, '/organization/employees/' + employee.id + '/deactivate', 'post', { expected_revision: revision, reason: 'Deactivate account' }],
  ['employee-reactivate', { ...employee, active: false }, { reason: 'Review existing MFA setup' }, '/organization/employees/' + employee.id + '/reactivate', 'post', { expected_revision: revision, reason: 'Review existing MFA setup' }],
  ['assignment-create', employee, { department_id: department.id, reason: 'Explicit administration assignment' }, '/organization/assignments', 'post', { expected_revision: revision, user_id: employee.id, department_id: department.id, reason: 'Explicit administration assignment' }],
  ['assignment-revoke', assignment, { reason: 'Remove this assignment' }, '/organization/assignments/' + assignment.id + '/revoke', 'post', { expected_revision: revision, reason: 'Remove this assignment' }],
];
for (const [operation, target, values, path, method, expected] of mutations) {
  test(`${operation} requires review/confirmation, sends exact payload and refreshes after backend success`, async () => {
    let submitted = false;
    const result = operation.startsWith('department-') ? { ...department, revision: newer } : operation.startsWith('employee-') ? { ...employee, revision: newer, ...(operation === 'employee-create' ? { active: false, organization_role: 'EMPLOYEE', requires_trusted_onboarding: true } : {}) } : { ...assignment, revision: newer };
    const requests = transport(config => {
      if (config.method === method && config.url === path) { submitted = true; return { status: operation.endsWith('-create') ? 201 : 200, data: result }; }
      return baseResponse(config);
    });
    const section = operation.startsWith('department-') ? 'departments' : operation === 'assignment-revoke' ? 'assignments' : 'employees';
    const controller = new OrganizationController(section, actor('SUPER_ADMIN'));
    await controller.load();
    controller.begin(operation, target);
    controller.review(values);
    assert.ok(controller.snapshot().editor.command);
    assert.equal(submitted, false);
    assert.equal(controller.snapshot().success, null);
    const reviewMarkup = renderToStaticMarkup(React.createElement(MutationForm, { editor: controller.snapshot().editor, controller, busy: false }));
    assert.match(reviewMarkup, /Review before confirming/);
    assert.match(reviewMarkup, /Confirm /);
    assert.doesNotMatch(reviewMarkup, /value="aaaaaaaaaaaaaaaa/);
    await controller.confirm();
    const mutation = requests.find(config => config.method === method && config.url === path);
    assert.ok(mutation);
    assert.deepEqual(JSON.parse(mutation.data), expected);
    assert.equal(mutation.withCredentials, true);
    assert.equal(mutation.headers.get('X-CSRF-Token'), 'test-csrf');
    assert.equal(mutation.headers.has('Authorization'), false);
    assert.ok(controller.snapshot().success);
    assert.equal(controller.snapshot().error, null);
    assert.ok(requests.filter(config => config.method === 'get' && config.url === '/organization/' + section).length >= 2);
    if (operation === 'employee-create') {
      assert.match(controller.snapshot().success, /inactive as EMPLOYEE/);
      assert.match(controller.snapshot().success, /not ready to sign in/);
    }
  });
}
test('department deactivation is never submitted by opening or cancelling its confirmation', async () => {
  const requests = transport(baseResponse);
  const controller = new OrganizationController('departments', actor('SUPER_ADMIN'));
  await controller.load();
  controller.begin('department-deactivate', department);
  controller.review({ reason: 'Review only' });
  controller.cancel();
  await controller.confirm();
  assert.equal(requests.some(r => r.method !== 'get'), false);
  assert.equal(controller.snapshot().editor, null);
});
test('duplicate confirmation clicks produce exactly one mutation while awaiting the backend', async () => {
  let resolve, calls = 0;
  transport(async config => {
    if (config.method === 'post' && config.url === '/organization/departments') {
      calls++; await new Promise(done => { resolve = done; }); return { data: department };
    }
    return baseResponse(config);
  });
  const controller = new OrganizationController('departments', actor('SUPER_ADMIN'));
  controller.begin('department-create');
  controller.review({ name: 'Fixture', reason: 'Review' });
  const first = controller.confirm();
  await new Promise(done => setImmediate(done));
  const second = controller.confirm();
  assert.equal(controller.snapshot().busy, true);
  assert.equal(calls, 1);
  assert.equal(controller.snapshot().success, null);
  resolve();
  await Promise.all([first, second]);
  assert.equal(calls, 1);
});
test('validation requires reason, revision, canonical role and explicit eligible assignment target', () => {
  assert.throws(() => prepareCommand('department-create', null, { name: 'Fixture', reason: ' ' }));
  assert.throws(() => prepareCommand('employee-role', { ...employee, revision: '' }, { organization_role: 'EMPLOYEE', reason: 'Review' }));
  assert.throws(() => prepareCommand('employee-role', employee, { organization_role: 'ADMIN', reason: 'Review' }));
  assert.throws(() => prepareCommand('assignment-create', { ...employee, organization_role: null }, { department_id: department.id, reason: 'Review' }));
  assert.throws(() => prepareCommand('assignment-create', employee, { reason: 'Review' }));
  assert.throws(() => prepareCommand('employee-update', employee, { name: employee.name, email: employee.email, home_department_id: employee.home_department_id, reason: 'Review' }));
  assert.equal(prepareCommand('employee-role', employee, { organization_role: 'EMPLOYEE', reason: 'Reviewed\nby operator' }).payload.reason, 'Reviewed\nby operator');
});
test('self-assignment is not offered or prepared', async () => {
  const current = { ...actor('SUPER_ADMIN'), id: employee.id };
  const controller = new OrganizationController('employees', current);
  controller.begin('assignment-create', employee);
  assert.equal(controller.snapshot().editor, null);
  assert.match(controller.snapshot().error, /yourself/);
});
test('employee details keep home membership separate from multiple active and revoked admin assignments', () => {
  const controller = new OrganizationController('employees', actor('SUPER_ADMIN'));
  const assignments = [assignment, { ...assignment, id: 'other-assignment', department_id: 'other-admin-department' }, revoked];
  const markup = view(controller, { page: page([employee]), detail: employee, selectedId: employee.id, history: page(assignments) });
  assert.match(markup, /Home department \(membership only\)/);
  assert.match(markup, /home-membership-only/);
  assert.match(markup, /explicit-admin-department/);
  assert.match(markup, /other-admin-department/);
  assert.match(markup, /Revoked/);
  assert.match(markup, /Active/);
  assert.equal((markup.match(/>Revoke assignment</g) || []).length, 2);
});
test('department roster can display multiple administrators', () => {
  const controller = new OrganizationController('departments', actor('SUPER_ADMIN'));
  const markup = view(controller, { page: page([department]), detail: department, history: page([assignment, { ...assignment, id: 'other-person-assignment', user_id: 'another-explicit-admin' }]) });
  assert.match(markup, /fictional-person/);
  assert.match(markup, /another-explicit-admin/);
});
test('Department Admin reads render only server-returned scope, with no mutation controls', async () => {
  const requests = transport(config => {
    if (config.url === '/organization/employees') return { data: page([employee], 20, 21) };
    return baseResponse(config);
  });
  const controller = new OrganizationController('employees', actor('DEPARTMENT_ADMIN'));
  await controller.load({ q: 'Fixture', offset: 20, home_department_id: 'server-validates-filter', limit: 20 }, employee.id);
  const markup = view(controller);
  assert.match(markup, /Employees in assigned departments/);
  assert.match(markup, /Fixture person/);
  assert.match(markup, /21–21 of 21 authorized records/);
  assert.doesNotMatch(markup, /Create employee identity|Edit profile|Change canonical role|Revoke assignment|Assign department administration/);
  assert.equal(requests.some(r => r.url === '/organization/assignments'), false);
  assert.deepEqual(requests[0].params, { limit: 20, offset: 20, q: 'Fixture', home_department_id: 'server-validates-filter' });
  assert.equal(Object.values(requests[0].params).includes('home-is-not-authority'), false);
  controller.begin('employee-role', employee);
  assert.equal(controller.snapshot().editor, null);
});
test('Department Admin cannot request the global assignment list through the screen controller', async () => {
  const requests = transport(baseResponse);
  const controller = new OrganizationController('assignments', actor('DEPARTMENT_ADMIN'));
  await controller.load();
  assert.equal(requests.length, 0);
  assert.match(controller.snapshot().error, /unavailable/);
});
for (const [status, code, message] of [[403, 'ADMINISTRATIVE_SCOPE_REQUIRED', /denied/], [404, 'NOT_FOUND', /outside/], [409, 'STALE_REVISION', /changed after review/], [409, 'DUPLICATE_DEPARTMENT', /normalized name/], [409, 'DUPLICATE_ACTIVE_ASSIGNMENT', /active assignment already exists/], [409, 'TRUSTED_ACCOUNT_SETUP_REQUIRED', /cannot be activated/], [409, 'LAST_SUPER_ADMIN_PROTECTED', /last usable Super Admin/]]) {
  test(`backend ${status} ${code} produces no false success or automatic retry`, async () => {
    let calls = 0;
    transport(config => {
      if (config.method !== 'get') { calls++; return { status, code }; }
      return baseResponse(config);
    });
    const controller = new OrganizationController('departments', actor('SUPER_ADMIN'));
    await controller.load();
    controller.begin('department-update', department);
    controller.review({ name: 'Changed', description: department.description, reason: 'Explicit review' });
    await controller.confirm();
    await controller.confirm();
    assert.equal(calls, 1);
    assert.equal(controller.snapshot().success, null);
    assert.equal(controller.snapshot().page, null);
    assert.equal(controller.snapshot().detail, null);
    assert.equal(controller.snapshot().editor, null);
    assert.match(controller.snapshot().error, message);
  });
}
test('stale revision reload requires a fresh review and uses the new server revision only then', async () => {
  const payloads = [];
  let changed = false;
  transport(config => {
    if (config.method === 'patch') { payloads.push(JSON.parse(config.data)); if (!changed) { changed = true; return { status: 409, code: 'STALE_REVISION' }; } return { data: { ...department, revision: newer } }; }
    if (config.url === '/organization/departments/' + department.id) return { data: { ...department, revision: changed ? newer : revision } };
    return baseResponse(config);
  });
  const controller = new OrganizationController('departments', actor('SUPER_ADMIN'));
  await controller.load({}, department.id);
  controller.begin('department-update', controller.snapshot().detail);
  controller.review({ name: 'Changed', description: department.description, reason: 'First review' });
  await controller.confirm();
  await controller.load({}, department.id);
  assert.equal(controller.snapshot().editor, null);
  controller.begin('department-update', controller.snapshot().detail);
  controller.review({ name: 'Changed after review', description: department.description, reason: 'Fresh independent review' });
  await controller.confirm();
  assert.deepEqual(payloads.map(value => value.expected_revision), [revision, newer]);
});
test('scope revocation removes previously rendered rows on reload denial', async () => {
  let denied = false;
  transport(config => denied ? { status: 403, code: 'ADMINISTRATIVE_SCOPE_REQUIRED' } : baseResponse(config));
  const controller = new OrganizationController('employees', actor('DEPARTMENT_ADMIN'));
  await controller.load();
  assert.match(view(controller), /Fixture person/);
  denied = true;
  await controller.load();
  assert.doesNotMatch(view(controller), /Fixture person/);
  assert.match(controller.snapshot().error, /denied/);
});
test('session expiry clears organization data and notifies the existing authentication flow', async () => {
  const auth = new AuthController({ profile: async () => actor('SUPER_ADMIN') });
  const disconnectAuth = auth.connect();
  await auth.restore();
  const controller = new OrganizationController('employees', actor('SUPER_ADMIN'));
  const disconnectOrg = controller.connect();
  transport(() => ({ status: 401 }));
  await controller.load();
  assert.equal(auth.snapshot().stage, 'session-ended');
  assert.equal(auth.snapshot().user, null);
  assert.equal(controller.snapshot().page, null);
  assert.match(controller.snapshot().error, /session ended/);
  disconnectAuth(); disconnectOrg();
});
test('older requests cannot replace new search results', async () => {
  let resolveOld;
  transport(async config => {
    if (config.params.q === 'old') { await new Promise(resolve => { resolveOld = resolve; }); return { data: page([{ ...employee, name: 'Obsolete fixture' }]) }; }
    return { data: page([employee]) };
  });
  const controller = new OrganizationController('employees', actor('DEPARTMENT_ADMIN'));
  const old = controller.load({ q: 'old' });
  await new Promise(resolve => setImmediate(resolve));
  await controller.load({ q: 'new' });
  resolveOld();
  await old;
  assert.equal(controller.snapshot().page.items[0].name, employee.name);
});
test('an old successful list response cannot restore organization rows after session rejection', async () => {
  let resolveOld;
  transport(async config => {
    if (config.url === '/fictional-protected') return { status: 401 };
    await new Promise(resolve => { resolveOld = resolve; });
    return { data: page([employee]) };
  });
  const controller = new OrganizationController('employees', actor('SUPER_ADMIN'));
  const disconnect = controller.connect();
  const old = controller.load();
  await new Promise(resolve => setImmediate(resolve));
  await assert.rejects(apiClient.get('/fictional-protected'));
  resolveOld();
  await old;
  assert.equal(controller.snapshot().page, null);
  assert.match(controller.snapshot().error, /session ended/);
  disconnect();
});
test('a confirmed write with failed refresh reports both confirmation and unavailable current data', async () => {
  let committed = false;
  transport(config => {
    if (config.method === 'post') { committed = true; return { status: 201, data: department }; }
    if (committed) return { status: 503, code: 'SERVICE_UNAVAILABLE' };
    return baseResponse(config);
  });
  const controller = new OrganizationController('departments', actor('SUPER_ADMIN'));
  controller.begin('department-create');
  controller.review({ name: 'New fixture', reason: 'Reviewed creation' });
  await controller.confirm();
  assert.match(controller.snapshot().success, /backend confirmed/);
  assert.ok(controller.snapshot().error);
  assert.equal(controller.snapshot().page, null);
  assert.equal(controller.snapshot().detail, null);
});
test('bounded pagination and assignment filters use only supported parameters', async () => {
  const requests = transport(() => ({ data: page([]) }));
  await organizationApi.list('assignments', { ...filters, active: 'false', user_id: employee.id, department_id: department.id, q: 'not-supported-for-assignments' });
  assert.deepEqual(requests[0].params, { limit: 20, offset: 0, active: false, user_id: employee.id, department_id: department.id });
  const controller = new OrganizationController('employees', actor('SUPER_ADMIN'));
  await controller.load({ offset: 100001 });
  await controller.load({ limit: 101 });
  assert.equal(requests.length, 1);
});
test('organization rendering allowlists fields and never displays credential or MFA internals', () => {
  const controller = new OrganizationController('employees', actor('SUPER_ADMIN'));
  const polluted = { ...employee, password_hash: 'DO-NOT-RENDER-HASH', mfa_secret: 'DO-NOT-RENDER-MFA', recovery_codes: ['DO-NOT-RENDER-CODE'], session_id: 'DO-NOT-RENDER-SESSION', security_generation: 'DO-NOT-RENDER-GENERATION' };
  const markup = view(controller, { page: page([polluted]), detail: polluted });
  assert.doesNotMatch(markup, /DO-NOT-RENDER/);
  assert.doesNotMatch(markup, /aaaaaaaaaaaaaaaaaaaaaaaa/);
  assert.match(markup, /Fixture person/);
});
test('loading, empty and unknown backend failures have explicit safe presentations', () => {
  const controller = new OrganizationController('departments', actor('SUPER_ADMIN'));
  assert.match(view(controller, { loading: true }), /Loading authorized records/);
  assert.match(view(controller, { page: page([]) }), /No records were returned/);
  assert.match(organizationError(new Error('never display exception secret')), /could not be confirmed/);
  assert.doesNotMatch(organizationError(new Error('never display exception secret')), /exception secret/);
});
