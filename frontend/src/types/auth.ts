import type { UserResponse } from './api';

export type OrganizationRole = 'SUPER_ADMIN' | 'DEPARTMENT_ADMIN' | 'EMPLOYEE';
export type ChallengePurpose = 'MFA_VERIFICATION' | 'MFA_ENROLLMENT' | 'ACCOUNT_RECOVERY' | 'REPLACEMENT_ENROLLMENT';
export interface Challenge {
  next_step: ChallengePurpose;
  challenge_id: string;
  challenge_secret: string;
}
export interface SessionResult {
  authenticated: true;
  csrf_token: string;
  recovery_codes?: string[];
}
export interface Provisioning {
  next_step: 'VERIFY_ENROLLMENT';
  provisioning_uri: string;
  qr_payload: string;
}
export type AuthStage = 'restoring' | 'login' | 'mfa' | 'enrollment' | 'replacement' |
  'recovery' | 'enrollment-unavailable' | 'recovery-codes' | 'authenticated' | 'session-ended';
export interface AuthState {
  user: UserResponse | null;
  stage: AuthStage;
  busy: boolean;
  message: string | null;
  provisioningUri: string | null;
  recoveryCodes: string[];
}
export interface AuthContextType extends AuthState {
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string, recover?: boolean) => Promise<void>;
  verify: (code: string) => Promise<void>;
  startEnrollment: () => Promise<void>;
  finishRecoveryCodes: () => void;
  restart: () => void;
  logout: () => Promise<void>;
}
