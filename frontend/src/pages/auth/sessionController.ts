import { sessionApi } from '../../api/sessions';
import type { SessionInfo, SessionPage } from '../../api/sessions';
import { onSessionRejected } from '../../api/client';

interface SessionState {
  page: SessionPage | null; pending: SessionInfo | null; loading: boolean; busy: boolean;
  error: string | null; message: string | null;
}
const empty = (): SessionState => ({ page: null, pending: null, loading: false, busy: false, error: null, message: null });
export class SessionController {
  private state = empty();
  private revision = 0;
  private listeners = new Set<() => void>();
  private userId?: string;
  constructor(userId?: string) { this.userId = userId; }
  snapshot = () => this.state;
  subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private publish(patch: Partial<SessionState>) { this.state = { ...this.state, ...patch }; this.listeners.forEach(listener => listener()); }
  connect = () => onSessionRejected(() => { this.revision++; this.publish({ ...empty(), error: 'Your session ended. Sign in again.' }); });
  load = async (offset = 0) => {
    if (this.state.busy || offset < 0 || offset > 100000) return;
    const revision = ++this.revision;
    this.publish({ page: null, pending: null, loading: true, error: null });
    try {
      const page = await sessionApi.list(this.userId, offset);
      if (revision === this.revision) this.publish({ page });
    } catch {
      if (revision === this.revision) this.publish({ error: 'Session information is unavailable or access was denied. Reload to recheck your current authority.' });
    } finally { if (revision === this.revision) this.publish({ loading: false }); }
  };
  requestRevoke = (session: SessionInfo) => {
    if (!this.state.busy && !this.state.loading && session.state === 'ACTIVE') this.publish({ pending: session, message: null, error: null });
  };
  cancel = () => { if (!this.state.busy) this.publish({ pending: null }); };
  confirm = async (reason: string) => {
    const pending = this.state.pending;
    if (!pending || this.state.busy) return;
    if (!reason.trim() || reason.trim().length > 2000) { this.publish({ error: 'Enter a reason (maximum 2000 characters). Exclude credentials and secrets.' }); return; }
    const revision = ++this.revision;
    this.publish({ busy: true, error: null, message: null });
    try {
      await sessionApi.revoke(pending.session_ref, reason.trim(), this.userId);
      if (revision !== this.revision) return;
      this.publish({ busy: false, pending: null, message: 'The backend confirmed session revocation.' });
      await this.load(this.state.page?.offset || 0);
    } catch {
      if (revision === this.revision) this.publish({ page: null, pending: null, error: 'Revocation was not confirmed. Reload current session state before retrying; the request may already have committed.' });
    } finally { if (revision === this.revision) this.publish({ busy: false }); }
  };
}
