import type { UserResponse } from '../types/api';
import type { OrganizationRole } from '../types/auth';

export function canonicalRole(user: UserResponse | null): OrganizationRole | null {
  const role = user?.organization_role;
  return role === 'SUPER_ADMIN' || role === 'DEPARTMENT_ADMIN' || role === 'EMPLOYEE' ? role : null;
}
export function isAdministrator(user: UserResponse | null): boolean {
  return ['SUPER_ADMIN', 'DEPARTMENT_ADMIN'].includes(canonicalRole(user) || '');
}
export function canPresentRoute(user: UserResponse | null, allowedRoles?: OrganizationRole[]): boolean {
  const role = canonicalRole(user);
  return role !== null && (!allowedRoles?.length || allowedRoles.includes(role));
}
export function getDefaultRouteForUser(user: UserResponse | null): string {
  if (!canonicalRole(user)) return '/identity-unavailable';
  return isAdministrator(user) ? '/admin' : '/employee';
}
