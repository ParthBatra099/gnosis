import { useEffect, useRef, useState, useSyncExternalStore } from 'react';
import type { FormEvent } from 'react';
import { useAuth } from '../../hooks/useAuth';
import { Link } from 'react-router-dom';
import { canonicalRole } from '../../utils/roles';
import { organizationApi } from '../../api/organization';
import { OrganizationController, organizationError } from './organizationController';
import type { Assignment, Department, Editor, Employee, Entity, Filters, Operation, OrganizationState, Page, Section } from '../../types/organization';
import './OrganizationPage.css';

const labels: Record<Operation, string> = {
  'department-create': 'Create department', 'department-update': 'Update department',
  'department-deactivate': 'Deactivate department', 'department-reactivate': 'Reactivate department',
  'employee-create': 'Create employee identity', 'employee-update': 'Update employee profile',
  'employee-role': 'Change canonical role', 'employee-deactivate': 'Deactivate employee',
  'employee-reactivate': 'Reactivate employee', 'assignment-create': 'Assign department administration',
  'assignment-revoke': 'Revoke department-admin assignment',
};

export function OrganizationPage({ section }: { section: Section }) {
  const { user } = useAuth();
  if (!user) return null;
  return <ConnectedOrganization key={section + user.id + user.organization_role} section={section} user={user} />;
}
function ConnectedOrganization({ section, user }: { section: Section; user: NonNullable<ReturnType<typeof useAuth>['user']> }) {
  const [controller] = useState(() => new OrganizationController(section, user));
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot);
  useEffect(() => {
    const disconnect = controller.connect();
    void controller.load();
    const refresh = () => {
      if (document.visibilityState === 'visible' && !controller.snapshot().editor) void controller.load();
    };
    window.addEventListener('focus', refresh);
    document.addEventListener('visibilitychange', refresh);
    return () => { disconnect(); window.removeEventListener('focus', refresh); document.removeEventListener('visibilitychange', refresh); };
  }, [controller]);
  return <OrganizationView controller={controller} state={state} />;
}

export function OrganizationView({ controller, state }: { controller: OrganizationController; state: OrganizationState }) {
  const superAdmin = canonicalRole(controller.actor) === 'SUPER_ADMIN';
  const departmental = canonicalRole(controller.actor) === 'DEPARTMENT_ADMIN';
  if ((!superAdmin && !departmental) || (controller.section === 'assignments' && !superAdmin)) {
    return <section className="org-page"><h1>Organization management unavailable</h1><p>No administrative navigation or controls are available for this canonical role.</p></section>;
  }
  const busy = state.loading || state.busy;
  return <section className="org-page" aria-busy={busy}>
    <header className="org-heading"><div><p className="org-eyebrow">ORGANIZATION</p><h1>{controller.section === 'departments' ? (superAdmin ? 'Departments' : 'Assigned departments') : controller.section === 'employees' ? (superAdmin ? 'Employee identities' : 'Employees in assigned departments') : 'Department-admin assignments'}</h1>
      <p>{superAdmin ? 'Organizational administration does not grant business-data access.' : 'Read-only view. The backend determines current assignment scope; home department is not administrative authority.'}</p></div>
      <button type="button" disabled={busy} onClick={() => void controller.load()}>Reload current data</button>
    </header>
    {state.error && <p className="org-notice org-error" role="alert">{state.error}</p>}
    {state.success && <p className="org-notice org-success" role="status">{state.success}</p>}
    {state.loading && <p role="status">Loading authorized records…</p>}
    {state.editor ? <MutationForm key={state.editor.operation + (state.editor.target?.id || '')} editor={state.editor} controller={controller} busy={state.busy} /> : <>
      <SearchForm key={controller.section} section={controller.section} filters={state.filters} busy={busy} search={filters => void controller.load({ ...filters, offset: 0 }, null, 0)} />
      {superAdmin && controller.section !== 'assignments' && <button type="button" disabled={busy} onClick={() => controller.begin(controller.section === 'departments' ? 'department-create' : 'employee-create')}>{controller.section === 'departments' ? 'Create department' : 'Create employee identity'}</button>}
      {controller.section === 'assignments' && <p>To create an assignment, open a canonical Department Admin in Employee identities and select “Assign department administration”. Each assignment is explicit and separate from home department.</p>}
      {state.page && <>
        <div className="org-table-wrap"><table><caption>{controller.section === 'assignments' ? 'Active and revoked department-admin assignment records' : 'Server-authorized ' + controller.section}</caption>
          <thead><tr>{controller.section === 'departments' ? <><th>Name</th><th>Department ID</th><th>Status</th><th>Details</th></> : controller.section === 'employees' ? <><th>Name / email</th><th>Canonical role</th><th>Home department</th><th>Account status</th><th>Details</th></> : <AssignmentHeaders actions={superAdmin} />}</tr></thead>
          <tbody>{state.page.items.map(item => controller.section === 'assignments' ? <AssignmentRow key={item.id} assignment={item as Assignment} revoke={superAdmin ? value => controller.begin('assignment-revoke', value) : undefined} busy={busy} /> : controller.section === 'departments' ? <DepartmentRow key={item.id} department={item as Department} open={() => void controller.load({}, item.id, 0)} busy={busy} /> : <EmployeeRow key={item.id} employee={item as Employee} open={() => void controller.load({}, item.id, 0)} busy={busy} />)}</tbody>
        </table></div>
        {!state.page.items.length && <p>No records were returned within your current scope and filters.</p>}
        <Pagination page={state.page} busy={busy} change={offset => void controller.load({ offset }, null, 0)} />
      </>}
      {state.detail && <Detail record={state.detail} section={controller.section} superAdmin={superAdmin} busy={busy} controller={controller} />}
      {state.history && <section className="org-panel" aria-label="Department-admin assignment history"><h2>Department-admin assignment history</h2>
        <p>These explicit administrative assignments are separate from an employee’s home department. Only server-authorized assignment rows are shown.</p>
        <div className="org-table-wrap"><table><thead><tr><AssignmentHeaders actions={superAdmin} /></tr></thead><tbody>{state.history.items.map(value => <AssignmentRow key={value.id} assignment={value} revoke={superAdmin ? item => controller.begin('assignment-revoke', item) : undefined} busy={busy} />)}</tbody></table></div>
        {!state.history.items.length && <p>No assignment history was returned in this scope.</p>}
        <Pagination page={state.history} busy={busy} change={offset => void controller.load({}, state.selectedId, offset)} />
      </section>}
    </>}
  </section>;
}

function SearchForm({ section, filters, busy, search }: { section: Section; filters: Filters; busy: boolean; search: (filters: Partial<Filters>) => void }) {
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    search({ q: String(data.get('q') || '').trim(), active: String(data.get('active') || '') as Filters['active'],
      home_department_id: String(data.get('home_department_id') || '').trim(), user_id: String(data.get('user_id') || '').trim(), department_id: String(data.get('department_id') || '').trim(), limit: Number(data.get('limit')) });
  }
  return <form className="org-search org-panel" onSubmit={submit}><fieldset disabled={busy}><legend>Search authorized records</legend>
    {section !== 'assignments' && <label>Search {section === 'employees' ? 'name or email' : 'department name'}<input name="q" maxLength={100} defaultValue={filters.q} /></label>}
    {section === 'employees' && <label>Home department ID filter<input name="home_department_id" maxLength={36} defaultValue={filters.home_department_id} /></label>}
    {section === 'assignments' && <><label>User ID filter<input name="user_id" maxLength={36} defaultValue={filters.user_id} /></label><label>Department ID filter<input name="department_id" maxLength={36} defaultValue={filters.department_id} /></label></>}
    <label>Status<select name="active" defaultValue={filters.active}><option value="">All</option><option value="true">Active</option><option value="false">{section === 'assignments' ? 'Revoked' : 'Inactive'}</option></select></label>
    <label>Rows per page<select name="limit" defaultValue={filters.limit}><option value="20">20</option><option value="50">50</option><option value="100">100</option></select></label>
    <button type="submit">Search</button>
  </fieldset></form>;
}
function Pagination({ page, busy, change }: { page: Page<Entity>; busy: boolean; change: (offset: number) => void }) {
  return <nav className="org-pagination" aria-label="Result pagination"><span>{page.total ? page.offset + 1 : 0}–{Math.min(page.offset + page.items.length, page.total)} of {page.total} authorized records</span>
    <button type="button" disabled={busy || page.offset === 0} onClick={() => change(Math.max(0, page.offset - page.limit))}>Previous</button>
    <button type="button" disabled={busy || page.offset + page.limit >= page.total || page.offset + page.limit > 100000} onClick={() => change(page.offset + page.limit)}>Next</button></nav>;
}
function DepartmentRow({ department, open, busy }: { department: Department; open: () => void; busy: boolean }) {
  return <tr><td>{department.name}</td><td><code>{department.id}</code></td><td>{department.active ? 'Active' : 'Inactive'}</td><td><button type="button" disabled={busy} onClick={open}>View {department.name}</button></td></tr>;
}
function EmployeeRow({ employee, open, busy }: { employee: Employee; open: () => void; busy: boolean }) {
  return <tr><td>{employee.name}<br />{employee.email}</td><td>{employee.organization_role || 'Canonical role unassigned'}</td><td><code>{employee.home_department_id}</code></td><td>{employee.active ? 'Active' : 'Inactive'}</td><td><button type="button" disabled={busy} onClick={open}>View {employee.name}</button></td></tr>;
}
function AssignmentHeaders({ actions }: { actions: boolean }) {
  return <><th>User ID</th><th>Administrative department</th><th>Assignment state</th><th>Assigned at / actor</th><th>Revoked at / actor</th>{actions && <th>Action</th>}</>;
}
function AssignmentRow({ assignment, revoke, busy }: { assignment: Assignment; revoke?: (assignment: Assignment) => void; busy: boolean }) {
  return <tr><td><code>{assignment.user_id}</code></td><td><code>{assignment.department_id}</code></td><td>{assignment.revoked_at ? 'Revoked' : 'Active'}</td><td><time>{assignment.assigned_at}</time><br />{assignment.assigned_by}</td><td>{assignment.revoked_at ? <><time>{assignment.revoked_at}</time><br />{assignment.revoked_by}</> : 'Not revoked'}</td>{revoke && <td>{!assignment.revoked_at && <button type="button" disabled={busy} onClick={() => revoke(assignment)}>Revoke assignment</button>}</td>}</tr>;
}
function Detail({ record, section, superAdmin, busy, controller }: { record: Entity; section: Section; superAdmin: boolean; busy: boolean; controller: OrganizationController }) {
  const employee = 'organization_role' in record ? record : null;
  const department = 'description' in record ? record : null;
  return <section className="org-panel" aria-label="Selected record details"><h2>{employee ? employee.name : department?.name}</h2><dl className="org-details"><dt>{employee ? 'User ID' : 'Department ID'}</dt><dd><code>{record.id}</code></dd>
    {employee && <><dt>Email</dt><dd>{employee.email}</dd><dt>Canonical organizational role</dt><dd>{employee.organization_role || 'Unassigned'}</dd><dt>Home department (membership only)</dt><dd><code>{employee.home_department_id}</code></dd><dt>Account status</dt><dd>{employee.active ? 'Active' : 'Inactive'}</dd></>}
    {department && <><dt>Description</dt><dd>{department.description || 'No description'}</dd><dt>Status</dt><dd>{department.active ? 'Active' : 'Inactive'}</dd></>}
  </dl>
    {employee && !employee.active && <p>Inactive identity. Trusted onboarding/MFA may be required before reactivation; this response does not expose onboarding completion or MFA status.</p>}
    {superAdmin && <div className="org-actions">
      <button type="button" disabled={busy} onClick={() => controller.begin(section === 'departments' ? 'department-update' : 'employee-update', record)}>Edit {employee ? 'profile' : 'department'}</button>
      <button type="button" disabled={busy} onClick={() => controller.begin(section === 'departments' ? (department?.active ? 'department-deactivate' : 'department-reactivate') : (employee?.active ? 'employee-deactivate' : 'employee-reactivate'), record)}>{(department?.active || employee?.active) ? 'Deactivate' : 'Reactivate'}</button>
      {employee && <button type="button" disabled={busy} onClick={() => controller.begin('employee-role', employee)}>Change canonical role</button>}
      {employee && <Link to={'/admin/employees/' + encodeURIComponent(employee.id) + '/sessions'}>Manage employee sessions</Link>}
      {employee?.organization_role === 'DEPARTMENT_ADMIN' && employee.id !== controller.actor.id && <button type="button" disabled={busy} onClick={() => controller.begin('assignment-create', employee)}>Assign department administration</button>}
    </div>}
  </section>;
}

function DepartmentPicker({ name, label, defaultValue = '' }: { name: string; label: string; defaultValue?: string }) {
  const [value, setValue] = useState(defaultValue);
  const [query, setQuery] = useState('');
  const [page, setPage] = useState<Page<Entity> | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const requestRevision = useRef(0);
  async function lookup(offset = 0) {
    const revision = ++requestRevision.current;
    setLoading(true); setPage(null); setError(null);
    try {
      const result = await organizationApi.list('departments', { q: query.trim(), active: 'true', offset, limit: 20, home_department_id: '', department_id: '', user_id: '' });
      if (revision === requestRevision.current) setPage(result);
    } catch (error) { if (revision === requestRevision.current) setError(organizationError(error)); }
    finally { if (revision === requestRevision.current) setLoading(false); }
  }
  return <div className="org-picker"><label>{label}<input name={name} required maxLength={36} value={value} onChange={event => setValue(event.target.value)} /></label>
    <p>Enter an explicit department ID, or search active departments below. Selection does not establish administrative authority.</p>
    <label>Find active department by name<input maxLength={100} value={query} onChange={event => setQuery(event.target.value)} /></label>
    <button type="button" disabled={loading} onClick={() => void lookup()}>Find departments</button>
    {loading && <p role="status">Finding departments…</p>}{error && <p role="alert">{error}</p>}
    {page && <><ul>{page.items.map(item => <li key={item.id}><button type="button" onClick={() => setValue(item.id)}>{'name' in item ? item.name : item.id} — {item.id}</button></li>)}</ul>{!page.items.length && <p>No active departments returned.</p>}<Pagination page={page} busy={loading} change={offset => void lookup(offset)} /></>}
  </div>;
}

export function MutationForm({ editor, controller, busy }: { editor: Editor; controller: OrganizationController; busy: boolean }) {
  const { operation, target, command } = editor;
  const department = target && 'description' in target ? target : null;
  const employee = target && 'organization_role' in target ? target : null;
  function review(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    controller.review(Object.fromEntries([...new FormData(event.currentTarget)].map(([key, value]) => [key, String(value)])));
  }
  return <section className="org-panel" aria-label={labels[operation]}><h2>{labels[operation]}</h2>
    {target && <p>Reviewed target: {'name' in target ? target.name : 'Assignment'} — <code>{target.id}</code></p>}
    {operation === 'employee-create' && <p>Creates an inactive EMPLOYEE identity only. No password, activation or MFA enrollment is provided. Trusted onboarding is required separately.</p>}
    {operation === 'employee-role' && <p>Use only canonical roles. Revoke all active department-admin assignments explicitly before changing away from DEPARTMENT_ADMIN. Identity changes can revoke sessions.</p>}
    {operation === 'assignment-create' && <p>Assigning administration is separate from home membership. A user may administer multiple departments, and a department may have multiple admins. No self-assignment is permitted.</p>}
    {operation === 'department-deactivate' && <p>Soft deactivation preserves history. The backend rejects departments with resources, active employees or active assignments.</p>}
    {operation === 'employee-reactivate' && <p>Reactivation requires existing trusted MFA setup and an active home department. This operation cannot perform onboarding.</p>}
    {(operation.startsWith('employee-') || operation.startsWith('assignment-')) && operation !== 'employee-create' && <p>Identity and assignment changes may invalidate the affected user’s sessions. Backend authorization and lifecycle checks remain required.</p>}
    {operation === 'assignment-revoke' && target && 'department_id' in target && <p>User <code>{target.user_id}</code> will lose this explicit assignment to department <code>{target.department_id}</code>. Assignment history is preserved.</p>}
    {command ? <div aria-label="Review and confirm change"><h3>Review before confirming</h3><dl className="org-details">{Object.entries(command.payload).filter(([key]) => key !== 'expected_revision').map(([key, value]) => <div key={key}><dt>{key.replaceAll('_', ' ')}</dt><dd>{value ?? '(clear value)'}</dd></div>)}</dl>
      <p>The backend will recheck authority and the revision captured when this record was reviewed. Confirming sends exactly this change. Do not include credentials in the reason.</p>
      <div className="org-actions"><button type="button" disabled={busy} onClick={() => void controller.confirm()}>{busy ? 'Submitting…' : 'Confirm ' + labels[operation].toLowerCase()}</button><button type="button" disabled={busy} onClick={controller.editAgain}>Edit review</button><button type="button" disabled={busy} onClick={controller.cancel}>Cancel</button></div>
    </div> : <form onSubmit={review}><fieldset disabled={busy}><legend>Change details</legend>
      {['department-create', 'department-update', 'employee-create', 'employee-update'].includes(operation) && <label>Name<input name="name" required maxLength={100} defaultValue={department?.name || employee?.name || ''} /></label>}
      {['department-create', 'department-update'].includes(operation) && <label>Description (blank clears it)<textarea name="description" maxLength={4000} defaultValue={department?.description || ''} /></label>}
      {['employee-create', 'employee-update'].includes(operation) && <><label>Email<input type="email" name="email" required maxLength={254} defaultValue={employee?.email || ''} /></label><DepartmentPicker name="home_department_id" label="Home department ID (membership, not administration)" defaultValue={employee?.home_department_id} /></>}
      {operation === 'employee-role' && <label>New canonical organizational role<select name="organization_role" required defaultValue={employee?.organization_role || 'EMPLOYEE'}><option value="SUPER_ADMIN">SUPER_ADMIN</option><option value="DEPARTMENT_ADMIN">DEPARTMENT_ADMIN</option><option value="EMPLOYEE">EMPLOYEE</option></select></label>}
      {operation === 'assignment-create' && <DepartmentPicker name="department_id" label="Administrative department ID (explicit assignment)" />}
      <label>Reason (required; exclude credentials and secrets)<textarea name="reason" required maxLength={2000} defaultValue="" /></label>
      <div className="org-actions"><button type="submit">Review change</button><button type="button" onClick={controller.cancel}>Cancel</button></div>
    </fieldset></form>}
  </section>;
}
