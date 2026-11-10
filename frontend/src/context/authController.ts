import { authApi } from '../api/auth';
import { onSessionRejected, setCsrfToken } from '../api/client';
import type { AuthState, Challenge } from '../types/auth';

const empty = (): AuthState => ({ user: null, stage: 'login', busy: false,
  message: null, provisioningUri: null, recoveryCodes: [] });
const status = (error: unknown): number | undefined =>
  (error as { response?: { status?: number } })?.response?.status;

// The provider and tests share this state machine. No browser storage or token state.
export class AuthController {
  private state: AuthState = { ...empty(), stage: 'restoring' };
  private ticket: Challenge | null = null;
  private revision = 0;
  private listeners = new Set<() => void>();
  private restoration: Promise<void> | null = null;
  private api: typeof authApi;
  constructor(api = authApi) { this.api = api; }
  snapshot = () => this.state;
  subscribe = (listener: () => void) => {
    this.listeners.add(listener);
    return () => { this.listeners.delete(listener); };
  };
  connect = () => onSessionRejected(this.sessionEnded);
  private publish(patch: Partial<AuthState>) {
    this.state = { ...this.state, ...patch };
    this.listeners.forEach(listener => listener());
  }
  restart = () => {
    this.revision++;
    this.ticket = null;
    setCsrfToken(null);
    this.publish(empty());
  };
  sessionEnded = () => {
    this.restart();
    this.publish({ stage: 'session-ended', message: 'Your session ended or was revoked. Sign in again.' });
  };
  restore = (): Promise<void> => {
    if (this.restoration) return this.restoration;
    const revision = this.revision;
    this.restoration = this.api.profile().then(user => {
      if (revision === this.revision) this.publish({ user, stage: 'authenticated' });
    }).catch(error => {
      if (revision === this.revision) {
        this.publish({ ...empty(), message: status(error) === 401 ? null : 'Unable to validate your session. Please try again.' });
      }
    }).finally(() => { this.restoration = null; });
    return this.restoration;
  };
  refresh = async () => {
    if (this.state.stage !== 'authenticated') return;
    const revision = this.revision;
    try {
      const user = await this.api.profile();
      if (revision === this.revision) this.publish({ user });
    } catch {
      if (revision === this.revision) this.sessionEnded();
    }
  };
  private acceptTicket(ticket: Challenge) {
    const stages = { MFA_VERIFICATION: 'mfa', MFA_ENROLLMENT: 'enrollment',
      ACCOUNT_RECOVERY: 'recovery', REPLACEMENT_ENROLLMENT: 'replacement' } as const;
    if (!ticket || !Object.hasOwn(stages, ticket.next_step) ||
      typeof ticket.challenge_id !== 'string' || !ticket.challenge_id ||
      typeof ticket.challenge_secret !== 'string' || !ticket.challenge_secret) {
      throw new Error('Invalid challenge response');
    }
    this.ticket = ticket;
    this.publish({ ...empty(), stage: stages[ticket.next_step], busy: true });
  }
  private run = async (operation: (revision: number) => Promise<void>) => {
    if (this.state.busy) return;
    const revision = ++this.revision;
    this.publish({ busy: true, message: null });
    try { await operation(revision); }
    catch (error) {
      if (revision !== this.revision) return;
      this.publish({ message: status(error) === 429 ? 'Too many attempts. Wait before trying again.' :
        status(error) === 401 ? 'Verification failed. Credentials or challenge may be invalid, expired or already used. Retry or start again.' :
        'Authentication could not be completed. Check your connection and try again. If enrollment was submitted, start again rather than reusing its secret.' });
    } finally {
      if (revision === this.revision) this.publish({ busy: false });
    }
  };
  login = (email: string, password: string, recover = false) => this.run(async revision => {
    this.ticket = null;
    this.publish({ user: null, provisioningUri: null, recoveryCodes: [] });
    const ticket = await this.api.login(email, password, recover);
    if (ticket?.next_step === 'REPLACEMENT_ENROLLMENT') throw new Error('Invalid password challenge');
    if (revision === this.revision) this.acceptTicket(ticket);
  });
  startEnrollment = () => this.run(async revision => {
    if (!this.ticket || !['MFA_ENROLLMENT', 'REPLACEMENT_ENROLLMENT'].includes(this.ticket.next_step)) return;
    const initial = this.ticket.next_step === 'MFA_ENROLLMENT';
    try {
      const data = await this.api.enroll(this.ticket);
      if (revision !== this.revision) return;
      if (data.next_step !== 'VERIFY_ENROLLMENT' || typeof data.provisioning_uri !== 'string' ||
        !data.provisioning_uri.startsWith('otpauth://totp/')) throw new Error('Invalid provisioning response');
      this.publish({ provisioningUri: data.provisioning_uri });
    } catch (error) {
      if (revision !== this.revision) return;
      if (initial && status(error) === 401) {
        this.ticket = null;
        this.publish({ stage: 'enrollment-unavailable', provisioningUri: null,
          message: 'Enrollment could not be authorized. Trusted independent onboarding is not configured in the current system. An expired or invalid challenge can also cause this response. Contact your organization’s onboarding operator; a password alone cannot enable enrollment.' });
      } else throw error;
    }
  });
  verify = (code: string) => this.run(async revision => {
    if (!this.ticket) throw new Error('Start again');
    if (this.ticket.next_step === 'ACCOUNT_RECOVERY') {
      const ticket = await this.api.recover(this.ticket, code);
      if (revision !== this.revision) return;
      if (ticket.next_step !== 'REPLACEMENT_ENROLLMENT') throw new Error('Invalid recovery response');
      this.acceptTicket(ticket);
      return;
    }
    const enrollment = this.ticket.next_step !== 'MFA_VERIFICATION';
    if (enrollment && !this.state.provisioningUri) throw new Error('Enrollment must start first');
    const data = await this.api.verify(this.ticket, code, enrollment);
    if (revision !== this.revision) return;
    if (data.authenticated !== true || typeof data.csrf_token !== 'string' || !data.csrf_token) throw new Error('Invalid session response');
    this.ticket = null;
    setCsrfToken(data.csrf_token);
    this.publish({ provisioningUri: null });
    const codes = Array.isArray(data.recovery_codes) && data.recovery_codes.every(code => typeof code === 'string') ? data.recovery_codes : [];
    // Issued once: retain delivery even if profile validation is temporarily down.
    // A protected 401 still clears everything through sessionEnded().
    if (codes.length) this.publish({ recoveryCodes: codes, stage: 'recovery-codes' });
    try {
      const user = await this.api.profile();
      if (revision !== this.revision) return;
      this.publish({ user, recoveryCodes: codes, stage: codes.length ? 'recovery-codes' : 'authenticated' });
    } catch (error) {
      if (revision === this.revision && !codes.length) this.publish(empty());
      throw error;
    }
  });
  finishRecoveryCodes = () => {
    if (this.state.stage === 'recovery-codes' && !this.state.busy) {
      this.publish({ recoveryCodes: [], stage: this.state.user ? 'authenticated' : 'login',
        message: this.state.user ? null : 'Recovery codes cleared from this screen. Sign in again to validate your session.' });
    }
  };
  logout = async () => {
    this.revision++;
    const revision = this.revision;
    this.ticket = null;
    this.publish({ ...empty(), busy: true });
    try {
      await this.api.logout();
    } catch (error) {
      if (revision === this.revision && status(error) !== 401) {
        this.publish({ message: 'Local sign-out is complete, but server revocation was not confirmed. Retry sign out before leaving this browser.' });
      }
    } finally {
      setCsrfToken(null);
      if (revision === this.revision) this.publish({ busy: false });
    }
  };
}
