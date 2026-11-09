import type { AuthState } from '../types/auth';
import { onSessionRejected, setCsrfToken } from '../api/client';
import { demoApi } from './api';

const empty = (): AuthState => ({ user: null, stage: 'login', busy: false,
  message: null, provisioningUri: null, recoveryCodes: [] });
const status = (error: unknown) => (error as { response?: { status?: number } })?.response?.status;

// Demo identity state only. No challenges, MFA credentials, tokens or browser storage.
export class DemoController {
  private state: AuthState = { ...empty(), stage: 'restoring' };
  private revision = 0;
  private listeners = new Set<() => void>();
  private restoration: Promise<void> | null = null;
  private api: typeof demoApi;
  constructor(api = demoApi) { this.api = api; }
  snapshot = () => this.state;
  subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  connect = () => onSessionRejected(this.sessionEnded);
  private publish(patch: Partial<AuthState>) {
    this.state = { ...this.state, ...patch };
    this.listeners.forEach(listener => listener());
  }
  restart = () => { this.revision++; setCsrfToken(null); this.publish(empty()); };
  sessionEnded = () => {
    const restoring = this.state.stage === 'restoring';
    this.restart();
    if (!restoring) this.publish({ stage: 'session-ended', message: 'Your demo session expired, was revoked, or the demo run is unavailable. Sign in again after the demo backend is available.' });
  };
  restore = (): Promise<void> => {
    if (this.restoration) return this.restoration;
    const revision = this.revision;
    this.restoration = this.api.profile().then(user => {
      if (revision === this.revision) this.publish({ user, stage: 'authenticated' });
    }).catch(error => {
      if (revision === this.revision) this.publish({ ...empty(), message: status(error) === 401 ? null :
        'Unable to verify local demo mode and session. Check the demo backend and try again.' });
    }).finally(() => { this.restoration = null; });
    return this.restoration;
  };
  refresh = async () => {
    if (this.state.stage !== 'authenticated') return;
    const revision = this.revision;
    try {
      const user = await this.api.profile();
      if (revision === this.revision) this.publish({ user });
    } catch { if (revision === this.revision) this.sessionEnded(); }
  };
  login = async (email: string, password: string) => {
    if (this.state.busy) return;
    const revision = ++this.revision;
    this.publish({ ...empty(), busy: true });
    try {
      await this.api.login(email, password);
      if (revision !== this.revision) return;
      const user = await this.api.profile();
      if (revision === this.revision) this.publish({ user, stage: 'authenticated' });
    } catch (error) {
      if (revision === this.revision) this.publish({ user: null, stage: 'login', message:
        status(error) === 429 ? 'Too many attempts. Wait before trying again.' :
        status(error) === 401 ? 'Sign-in failed. Check your fictional demo credentials and account status.' :
        'Demo sign-in unavailable. Verify the local demo backend and its mode, then try again.' });
    } finally { if (revision === this.revision) this.publish({ busy: false }); }
  };
  logout = async () => {
    const revision = ++this.revision;
    this.publish({ ...empty(), busy: true });
    try { await this.api.logout(); }
    catch (error) {
      if (revision === this.revision && status(error) !== 401)
        this.publish({ message: 'Local sign-out is complete, but server revocation was not confirmed. Retry sign out before leaving this browser.' });
    } finally {
      setCsrfToken(null);
      if (revision === this.revision) this.publish({ busy: false });
    }
  };
}
