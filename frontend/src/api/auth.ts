import { apiClient, setCsrfToken } from './client';
import type { Challenge, Provisioning, SessionResult } from '../types/auth';
import type { UserResponse } from '../types/api';

export const authApi = {
  async login(email: string, password: string, recover = false): Promise<Challenge> {
    return (await apiClient.post('/auth/login', { email, password, intent: recover ? 'recover' : 'login' })).data;
  },
  async enroll(ticket: Challenge): Promise<Provisioning> {
    return (await apiClient.post('/auth/mfa/enroll', ticketBody(ticket))).data;
  },
  async verify(ticket: Challenge, code: string, enrollment: boolean): Promise<SessionResult> {
    const path = enrollment ? '/auth/mfa/enroll/verify' : '/auth/mfa/verify';
    return (await apiClient.post(path, { ...ticketBody(ticket), code })).data;
  },
  async recover(ticket: Challenge, code: string): Promise<Challenge> {
    return (await apiClient.post('/auth/recovery/verify', { ...ticketBody(ticket), code })).data;
  },
  async profile(): Promise<UserResponse> {
    return (await apiClient.get('/auth/me')).data;
  },
  async logout(): Promise<void> {
    await apiClient.post('/auth/logout');
    setCsrfToken(null);
  },
};
function ticketBody(ticket: Challenge) {
  return { challenge_id: ticket.challenge_id, challenge_secret: ticket.challenge_secret };
}
