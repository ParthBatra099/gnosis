import { useEffect, useState, useSyncExternalStore } from 'react';
import { useParams } from 'react-router-dom';
import type { FormEvent } from 'react';
import { SessionController } from './sessionController';
import '../admin/OrganizationPage.css';

export function SessionManagement() {
  const { userId } = useParams();
  return <ConnectedSessions key={userId || 'own'} userId={userId} />;
}
function ConnectedSessions({ userId }: { userId?: string }) {
  const [controller] = useState(() => new SessionController(userId));
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot);
  useEffect(() => {
    const disconnect = controller.connect();
    void controller.load();
    const refresh = () => { if (document.visibilityState === 'visible' && !controller.snapshot().pending) void controller.load(controller.snapshot().page?.offset || 0); };
    window.addEventListener('focus', refresh);
    return () => { disconnect(); window.removeEventListener('focus', refresh); };
  }, [controller]);
  function confirm(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void controller.confirm(String(new FormData(event.currentTarget).get('reason') || ''));
  }
  return <section className="org-page"><h1>{userId ? 'Employee session management' : 'My sessions'}</h1>
    {userId && <p>Target user: {userId}. The backend requires current Super Admin authority for this screen.</p>}
    <p>Session references are management handles, not authentication credentials. Revoking one session preserves other sessions and recovery inventory.</p>
    <button type="button" disabled={state.loading || state.busy} onClick={() => void controller.load(state.page?.offset || 0)}>Reload sessions</button>
    {state.loading && <p role="status">Loading sessions...</p>}{state.error && <p role="alert">{state.error}</p>}{state.message && <p role="status">{state.message}</p>}
    {state.pending && <form className="org-panel" onSubmit={confirm}><h2>Confirm session revocation</h2>
      <p>Created {state.pending.created_at}. {state.pending.is_current ? 'This is your current session. Revocation will return you to sign-in.' : 'Subsequent requests using this session will be rejected.'}</p>
      <label>Reason (exclude credentials and secrets)<textarea name="reason" required maxLength={2000} disabled={state.busy} /></label>
      <button type="submit" disabled={state.busy}>{state.busy ? 'Revoking...' : 'Confirm revocation'}</button><button type="button" disabled={state.busy} onClick={controller.cancel}>Cancel</button>
    </form>}
    {state.page && <><div className="org-table-wrap"><table><caption>Server-authorized sessions</caption><thead><tr><th>Created</th><th>Last activity</th><th>Absolute expiry</th><th>State</th><th>Action</th></tr></thead>
      <tbody>{state.page.items.map(session => <tr key={session.session_ref}><td>{session.created_at}{session.is_current && ' (current)'}</td><td>{session.last_activity_at}</td><td>{session.expires_at}</td><td>{session.state}</td><td>{session.state === 'ACTIVE' && <button type="button" disabled={state.busy || !!state.pending} onClick={() => controller.requestRevoke(session)}>Revoke session</button>}</td></tr>)}</tbody></table></div>
      {!state.page.items.length && <p>No sessions returned.</p>}<nav className="org-pagination" aria-label="Session pagination"><span>{state.page.total} sessions</span>
        <button type="button" disabled={state.busy || state.page.offset === 0} onClick={() => void controller.load(Math.max(0, state.page!.offset - 20))}>Previous</button>
        <button type="button" disabled={state.busy || state.page.offset + 20 >= state.page.total || state.page.offset + 20 > 100000} onClick={() => void controller.load(state.page!.offset + 20)}>Next</button></nav></>}
  </section>;
}
