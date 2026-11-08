import { apiClient } from './client';

export interface SessionInfo {
  session_ref: string;
  created_at: string;
  last_activity_at: string;
  expires_at: string;
  state: 'ACTIVE' | 'EXPIRED' | 'REVOKED' | 'INVALIDATED';
  is_current: boolean;
}
export interface SessionPage { items: SessionInfo[]; total: number; limit: number; offset: number }
const prefix = (userId?: string) => userId ? '/organization/employees/' + encodeURIComponent(userId) + '/sessions' : '/auth/sessions';
export const sessionApi = {
  async list(userId?: string, offset = 0): Promise<SessionPage> {
    return (await apiClient.get(prefix(userId), { params: { limit: 20, offset } })).data;
  },
  async revoke(sessionRef: string, reason: string, userId?: string): Promise<void> {
    await apiClient.post(prefix(userId) + '/' + encodeURIComponent(sessionRef) + '/revoke', { reason });
  },
};
