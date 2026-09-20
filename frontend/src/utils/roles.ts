import type { UserResponse } from '../types/api';

export function isAdminOrSecurity(user: UserResponse | null): boolean {
  if (!user) return false;
  const role = user.role.toLowerCase();
  return role === 'admin' || role === 'security_officer';
}

export function isManagerOrEmployee(user: UserResponse | null): boolean {
  if (!user) return false;
  const role = user.role.toLowerCase();
  return role === 'manager' || role === 'employee';
}

export function getDefaultRouteForUser(user: UserResponse | null): string {
  if (isAdminOrSecurity(user)) {
    return '/admin/dashboard';
  }
  return '/employee/dashboard';
}