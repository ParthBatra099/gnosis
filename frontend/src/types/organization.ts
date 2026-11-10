import type { OrganizationRole } from './auth';

export interface Department {
  id: string; name: string; description: string | null; active: boolean; revision: string;
}
export interface Employee {
  id: string; name: string; email: string; organization_role: OrganizationRole | null;
  home_department_id: string; active: boolean; revision: string;
  requires_trusted_onboarding?: boolean;
}
export interface Assignment {
  id: string; user_id: string; department_id: string; assigned_at: string; assigned_by: string;
  revoked_at: string | null; revoked_by: string | null; revision: string;
}
export interface Page<T> { items: T[]; total: number; limit: number; offset: number }
export type Section = 'departments' | 'employees' | 'assignments';
export type Entity = Department | Employee | Assignment;
export interface Filters {
  q: string; active: '' | 'true' | 'false'; offset: number; limit: number;
  home_department_id: string; user_id: string; department_id: string;
}
export type Operation = 'department-create' | 'department-update' | 'department-deactivate' | 'department-reactivate' |
  'employee-create' | 'employee-update' | 'employee-role' | 'employee-deactivate' | 'employee-reactivate' |
  'assignment-create' | 'assignment-revoke';
export interface Command { operation: Operation; targetId?: string; payload: Record<string, string | null> }
export interface Editor { operation: Operation; target: Entity | null; command: Command | null }
export interface OrganizationState {
  page: Page<Entity> | null; detail: Entity | null; history: Page<Assignment> | null;
  selectedId: string | null; filters: Filters; historyOffset: number;
  loading: boolean; busy: boolean; error: string | null; success: string | null;
  editor: Editor | null;
}
