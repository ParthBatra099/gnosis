import { organizationApi } from '../../api/organization';
import { onSessionRejected } from '../../api/client';
import { canonicalRole } from '../../utils/roles';
import type { UserResponse } from '../../types/api';
import type { Command, Employee, Entity, Filters, Operation, OrganizationState, Section } from '../../types/organization';

const initialFilters = (): Filters => ({ q: '', active: '', limit: 20, offset: 0, home_department_id: '', department_id: '', user_id: '' });
const initialState = (): OrganizationState => ({ page: null, detail: null, history: null, selectedId: null,
  filters: initialFilters(), historyOffset: 0, loading: false, busy: false, error: null, success: null, editor: null });
const errorStatus = (error: unknown) => (error as { response?: { status?: number } })?.response?.status;
export function organizationError(error: unknown): string {
  const status = errorStatus(error);
  const code = (error as { response?: { data?: { detail?: { code?: string } } } })?.response?.data?.detail?.code;
  const explanations: Record<string, string> = {
    STALE_REVISION: 'This record changed after review. Reload current data, review it and submit a new confirmation. Nothing was automatically overwritten.',
    DUPLICATE_DEPARTMENT: 'A department with that normalized name already exists. Choose a different name.',
    DUPLICATE_EMPLOYEE: 'An employee identity with that email already exists.',
    DUPLICATE_ACTIVE_ASSIGNMENT: 'An active assignment already exists for this user and department.',
    ASSIGNMENT_ALREADY_REVOKED: 'This assignment has already been revoked. Reload its history.',
    IDENTITY_INVARIANT: 'The identity change was rejected. Revoke active department assignments before changing away from Department Admin; review the current identity state.',
    IDENTITY_CONFLICT: 'The change conflicts with existing identity data. Reload and review before retrying.',
    DEPARTMENT_HAS_LIVE_REFERENCES: 'This department still has resources, active employees or active admin assignments. It cannot be deactivated.',
    DEPARTMENT_INACTIVE: 'The selected department is inactive.',
    TRUSTED_ACCOUNT_SETUP_REQUIRED: 'This identity cannot be activated until trusted onboarding establishes MFA. Creating an identity does not activate its account.',
    LAST_SUPER_ADMIN_PROTECTED: 'The last usable Super Admin cannot be deactivated or demoted.',
    SELF_ASSIGNMENT_PROHIBITED: 'You cannot grant yourself department administration.',
    SELF_SCOPE_CHANGE_PROHIBITED: 'Another authorized Super Admin must review a change to your home department.',
    INVALID_INPUT: 'The backend rejected the input. Check the fields and required reason.',
  };
  if (status === 401) return 'Your session ended. Sign in again.';
  if (status === 403) return code && explanations[code] ? explanations[code] : 'The backend denied this operation. Your administrative scope may have changed. Reload before continuing.';
  if (status === 404) return 'The record is unavailable or outside your current authorized scope.';
  if (code && explanations[code]) return explanations[code];
  if (status === 409) return 'The change conflicts with current data. Reload and review; no automatic retry was made.';
  return 'The operation could not be confirmed. Check the connection and reload current data before retrying. A submitted change may already have committed.';
}

const required = (values: Record<string, string>, field: string, max: number) => {
  const value = (values[field] || '').trim();
  const hasControl = [...value].some(char => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127);
  if (!value || value.length > max || (field !== 'reason' && hasControl)) throw new Error('Check ' + field.replaceAll('_', ' ') + ' (required, maximum ' + max + ' characters).');
  return value;
};
// Build an allowlisted command from the exact record reviewed by the operator.
export function prepareCommand(operation: Operation, target: Entity | null, values: Record<string, string>): Command {
  const payload: Record<string, string | null> = { reason: required(values, 'reason', 2000) };
  if (!['department-create', 'employee-create'].includes(operation)) {
    if (!target || !/^[0-9a-f]{64}$/.test(target.revision)) throw new Error('Reload the current record before making this change.');
    payload.expected_revision = target.revision;
  }
  if (operation === 'department-create' || operation === 'department-update') {
    const name = required(values, 'name', 100);
    const description = values.description || null;
    if (description && description.length > 4000) throw new Error('Description must be at most 4000 characters.');
    if (operation === 'department-create' || (target && 'description' in target && target.name !== name)) payload.name = name;
    if (operation === 'department-create' || (target && 'description' in target && target.description !== description)) payload.description = description;
    if (operation === 'department-update' && !('name' in payload) && !('description' in payload)) throw new Error('Change department metadata before reviewing.');
  }
  if (operation === 'employee-create' || operation === 'employee-update') {
    const employee = target as Employee | null;
    for (const [field, max] of [['name', 100], ['email', 254], ['home_department_id', 36]] as const) {
      const value = required(values, field, max);
      if (field === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) throw new Error('Enter a valid email address.');
      if (operation === 'employee-create' || employee?.[field] !== value) payload[field] = value;
    }
    if (operation === 'employee-update' && Object.keys(payload).length === 2) throw new Error('Change a profile field before reviewing.');
  }
  if (operation === 'employee-role') {
    const role = required(values, 'organization_role', 32);
    if (!['SUPER_ADMIN', 'DEPARTMENT_ADMIN', 'EMPLOYEE'].includes(role)) throw new Error('Choose a canonical organizational role.');
    payload.organization_role = role;
  }
  if (operation === 'assignment-create') {
    if (!target || !('organization_role' in target) || target.organization_role !== 'DEPARTMENT_ADMIN') throw new Error('Select a canonical Department Admin identity.');
    payload.user_id = target.id;
    payload.department_id = required(values, 'department_id', 36);
  }
  return { operation, targetId: target?.id, payload };
}

export class OrganizationController {
  private state = initialState();
  private listeners = new Set<() => void>();
  private revision = 0;
  readonly section: Section;
  readonly actor: UserResponse;
  private api: typeof organizationApi;
  constructor(section: Section, actor: UserResponse, api = organizationApi) { this.section = section; this.actor = actor; this.api = api; }
  snapshot = () => this.state;
  subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private publish(patch: Partial<OrganizationState>) { this.state = { ...this.state, ...patch }; this.listeners.forEach(listener => listener()); }
  connect = () => onSessionRejected(() => { this.revision++; this.publish({ ...initialState(), error: 'Your session ended. Sign in again.' }); });
  cancel = () => { if (!this.state.busy) this.publish({ editor: null, error: null }); };
  editAgain = () => { if (this.state.editor && !this.state.busy) this.publish({ editor: { ...this.state.editor, command: null } }); };
  load = async (filters: Partial<Filters> = {}, selectedId = this.state.selectedId, historyOffset = this.state.historyOffset) => {
    if (this.state.busy) return;
    const role = canonicalRole(this.actor);
    if (!role || role === 'EMPLOYEE' || (this.section === 'assignments' && role !== 'SUPER_ADMIN')) {
      this.publish({ ...initialState(), error: 'Organization management is unavailable for this canonical role.' }); return;
    }
    const query = { ...this.state.filters, ...filters };
    if (query.limit < 1 || query.limit > 100 || query.offset < 0 || query.offset > 100000 || query.q.length > 100 || historyOffset < 0 || historyOffset > 100000) return;
    const revision = ++this.revision;
    this.publish({ filters: query, selectedId, historyOffset, page: null, detail: null, history: null, editor: null, loading: true, error: null });
    try {
      const page = await this.api.list(this.section, query);
      let detail: Entity | null = null;
      let history = null;
      if (selectedId && this.section !== 'assignments') {
        detail = await this.api.detail(this.section, selectedId);
        history = await this.api.history(this.section, selectedId, historyOffset);
      }
      if (revision === this.revision) this.publish({ page, detail, history });
    } catch (error) {
      if (revision === this.revision) this.publish({ page: null, detail: null, history: null, error: organizationError(error) });
    } finally { if (revision === this.revision) this.publish({ loading: false }); }
  };
  begin = (operation: Operation, target: Entity | null = null) => {
    if (this.state.busy || this.state.loading || canonicalRole(this.actor) !== 'SUPER_ADMIN') return;
    if (operation === 'assignment-create' && target?.id === this.actor.id) {
      this.publish({ error: 'You cannot grant yourself department administration.' }); return;
    }
    this.publish({ editor: { operation, target: target ? { ...target } : null, command: null }, error: null, success: null });
  };
  review = (values: Record<string, string>) => {
    const editor = this.state.editor;
    if (!editor || this.state.busy) return;
    try {
      const command = prepareCommand(editor.operation, editor.target, values);
      this.publish({ editor: { ...editor, command }, error: null });
    } catch (error) { this.publish({ error: error instanceof Error ? error.message : 'Check the input.' }); }
  };
  confirm = async () => {
    const command = this.state.editor?.command;
    if (!command || this.state.busy || canonicalRole(this.actor) !== 'SUPER_ADMIN') return;
    const revision = ++this.revision;
    this.publish({ busy: true, success: null, error: null });
    let result: Entity;
    try {
      result = await this.api.execute(command);
    } catch (error) {
      if (revision === this.revision) this.publish({ busy: false, editor: null, page: null, detail: null, history: null, error: organizationError(error) });
      return;
    }
    if (revision !== this.revision) return;
    const created = command.operation === 'employee-create';
    this.publish({ busy: false, editor: null, success: created ? 'Identity created inactive as EMPLOYEE. Trusted onboarding is required; the account is not ready to sign in.' : 'The backend confirmed the change.' });
    const selectedId = command.operation.endsWith('-create') && command.operation !== 'assignment-create' ? result.id : this.state.selectedId;
    await this.load({}, selectedId, 0);
  };
}
