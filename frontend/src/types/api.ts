export interface UserResponse {
  id: string;
  name: string;
  email: string;
  role: string;
  department_id: string | null;
  active: boolean;
}