import { apiClient } from './client';
import type { Assignment, Command, Department, Employee, Entity, Filters, Page, Section } from '../types/organization';

const id = (value: string) => encodeURIComponent(value);
export const organizationApi = {
  async list(section: Section, filters: Filters): Promise<Page<Entity>> {
    const params: Record<string, string | number | boolean> = { limit: filters.limit, offset: filters.offset };
    if (filters.active !== '') params.active = filters.active === 'true';
    if (section !== 'assignments' && filters.q) params.q = filters.q;
    if (section === 'employees' && filters.home_department_id) params.home_department_id = filters.home_department_id;
    if (section === 'assignments') {
      if (filters.user_id) params.user_id = filters.user_id;
      if (filters.department_id) params.department_id = filters.department_id;
    }
    return (await apiClient.get<Page<Entity>>('/organization/' + section, { params })).data;
  },
  async detail(section: 'departments' | 'employees', identifier: string): Promise<Department | Employee> {
    return (await apiClient.get('/organization/' + section + '/' + id(identifier))).data;
  },
  async history(section: 'departments' | 'employees', identifier: string, offset = 0): Promise<Page<Assignment>> {
    return (await apiClient.get('/organization/' + section + '/' + id(identifier) + '/assignments', { params: { limit: 20, offset } })).data;
  },
  async execute(command: Command): Promise<Entity> {
    const { operation, targetId, payload } = command;
    const routes: Record<typeof operation, [string, 'post' | 'patch']> = {
      'department-create': ['/departments', 'post'],
      'department-update': ['/departments/' + id(targetId || ''), 'patch'],
      'department-deactivate': ['/departments/' + id(targetId || '') + '/deactivate', 'post'],
      'department-reactivate': ['/departments/' + id(targetId || '') + '/reactivate', 'post'],
      'employee-create': ['/employees', 'post'],
      'employee-update': ['/employees/' + id(targetId || ''), 'patch'],
      'employee-role': ['/employees/' + id(targetId || '') + '/role', 'post'],
      'employee-deactivate': ['/employees/' + id(targetId || '') + '/deactivate', 'post'],
      'employee-reactivate': ['/employees/' + id(targetId || '') + '/reactivate', 'post'],
      'assignment-create': ['/assignments', 'post'],
      'assignment-revoke': ['/assignments/' + id(targetId || '') + '/revoke', 'post'],
    };
    const [path, method] = routes[operation];
    return (await apiClient.request({ method, url: '/organization' + path, data: payload })).data;
  },
};
