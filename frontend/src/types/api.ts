export interface UserResponse {
  id: string;
  name: string;
  email: string;
  role: string;
  organization_role: import('./auth').OrganizationRole | null;
  department_id: string | null;
  active: boolean;
}
