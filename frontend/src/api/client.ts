import axios from 'axios';
import { API_BASE_URL } from '../utils/constants';

// Cookies belong to the browser. Only the CSRF header value lives in memory.
let csrfToken: string | null = null;
let csrfRequest: Promise<string> | null = null;
let transportGeneration = 0;
const sessionListeners = new Set<() => void>();
export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: true,
  headers: { 'Content-Type': 'application/json' },
});
export function setCsrfToken(value: string | null) {
  transportGeneration++;
  csrfToken = value;
  csrfRequest = null;
}
export function onSessionRejected(listener: () => void) {
  sessionListeners.add(listener);
  return () => { sessionListeners.delete(listener); };
}
export async function ensureCsrf(): Promise<string> {
  if (csrfToken) return csrfToken;
  if (!csrfRequest) {
    const generation = transportGeneration;
    csrfRequest = apiClient.get('/auth/csrf').then(({ data }) => {
      if (typeof data.csrf_token !== 'string' || !data.csrf_token) throw new Error('Invalid CSRF response');
      if (generation !== transportGeneration) throw new Error('Authentication changed; retry the operation');
      const token: string = data.csrf_token;
      csrfToken = token;
      return token;
    }).finally(() => { if (generation === transportGeneration) csrfRequest = null; });
  }
  return csrfRequest!;
}
apiClient.interceptors.request.use(async config => {
  config.headers.delete('Authorization');
  if (!['get', 'head', 'options'].includes((config.method || 'get').toLowerCase())) {
    config.headers.set('X-CSRF-Token', await ensureCsrf());
  }
  return config;
});
const publicAuthPosts = new Set(['/auth/login', '/auth/mfa/enroll', '/auth/mfa/enroll/verify', '/auth/mfa/verify', '/auth/recovery/verify']);
apiClient.interceptors.response.use(response => response, error => {
  if (error.response?.status === 401 && !publicAuthPosts.has(error.config?.url)) {
    setCsrfToken(null);
    sessionListeners.forEach(listener => listener());
  } else if (error.response?.status === 403) {
    // Never automatically replay a state-changing request.
    setCsrfToken(null);
  }
  return Promise.reject(error);
});
