import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { LockKeyhole, Shield } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { getDefaultRouteForUser } from '../utils/roles';

export function DemoLogin() {
  const auth = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [validation, setValidation] = useState('');
  useEffect(() => {
    if (auth.isAuthenticated) navigate(getDefaultRouteForUser(auth.user), { replace: true });
  }, [auth.isAuthenticated, auth.user, navigate]);
  async function submit(event: FormEvent) {
    event.preventDefault();
    setValidation('');
    if (!email.trim() || !password) { setValidation('Enter your fictional demo email and password.'); return; }
    const submitted = password;
    setPassword('');
    await auth.login(email.trim(), submitted);
  }
  return <main className="demo-login">
    <section className="demo-introduction"><div className="demo-wordmark"><Shield aria-hidden="true" /> GNOSIS</div>
      <p className="demo-eyebrow">LOCAL EVALUATION WORKSPACE</p><h1>Security decisions.<br />Visible evidence.</h1>
      <p>Explore organizational authority, controlled access and investigative evidence with fictional accounts and persisted activity.</p>
      <div className="demo-principles"><span>Canonical identity</span><span>Department boundaries</span><span>Auditable activity</span></div>
    </section>
    <section className="demo-login-card" aria-labelledby="demo-login-title"><LockKeyhole className="demo-login-icon" aria-hidden="true" />
      <p className="demo-eyebrow">PASSWORD-ONLY DEMONSTRATION</p><h2 id="demo-login-title">{auth.isLoading ? 'Checking your demo session…' : auth.stage === 'session-ended' ? 'Your session has ended' : 'Sign in to the local demo'}</h2>
      <p>Use an account explicitly provisioned for this demonstration. Backend authorization remains enforced.</p>
      {(validation || auth.message) && <div className="demo-error" role="alert">{validation || auth.message}</div>}
      {auth.isLoading ? <p role="status">Verifying demo backend mode and session…</p> : <form onSubmit={submit} className="demo-form">
        <label htmlFor="demo-email">Fictional account email<input id="demo-email" type="email" autoComplete="username" required
          value={email} disabled={auth.busy} onChange={event => setEmail(event.target.value)} /></label>
        <label htmlFor="demo-password">Password<input id="demo-password" type="password" autoComplete="current-password" required maxLength={1024}
          value={password} disabled={auth.busy} onChange={event => setPassword(event.target.value)} /></label>
        <button type="submit" disabled={auth.busy}>{auth.busy ? 'Verifying demo account…' : 'Sign in to demo'}</button>
      </form>}
      <button className="demo-secondary" type="button" disabled={auth.busy || auth.isLoading} onClick={() => void auth.logout()}>Sign out an existing demo session</button>
      <p className="demo-footnote">MFA is not being demonstrated. Normal GNOSIS sign-in continues to require an authenticator. No credentials are supplied by this screen.</p>
    </section>
  </main>;
}
