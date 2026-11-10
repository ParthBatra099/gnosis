import { apiClient, DEMO_AUTH_MODE, setCsrfToken } from '../api/client';
import type { UserResponse } from '../types/api';

export const demoApi = {
  async verifyMode() {
    const { data } = await apiClient.get('/health');
    if (data.auth_mode !== DEMO_AUTH_MODE || data.demo_mode !== true)
      throw new Error('The selected backend is not the local demo application.');
  },
  async mode() {
    // Explicit CSRF bootstrap for login/logout. Never infer mode from /me.
    const { data } = await apiClient.get('/auth/csrf');
    if (data.auth_mode !== DEMO_AUTH_MODE || typeof data.csrf_token !== 'string' || !data.csrf_token)
      throw new Error('The selected backend is not the local demo application.');
    setCsrfToken(data.csrf_token);
  },
  async login(email: string, password: string) {
    await this.mode();
    const { data } = await apiClient.post('/auth/login', { email, password, intent: 'login' });
    if (data.auth_mode !== DEMO_AUTH_MODE || data.authenticated !== true ||
        typeof data.csrf_token !== 'string' || !data.csrf_token || data.next_step || data.recovery_codes)
      throw new Error('Invalid local demo session response.');
    setCsrfToken(data.csrf_token);
  },
  async profile(): Promise<UserResponse> {
    // Do not rotate the CSRF cookie while a concurrent business mutation is pending.
    await this.verifyMode();
    return (await apiClient.get('/auth/me')).data;
  },
  async logout() {
    await this.mode();
    await apiClient.post('/auth/logout');
    setCsrfToken(null);
  },
};
