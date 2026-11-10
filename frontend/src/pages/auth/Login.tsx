import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { Lock, ShieldCheck } from 'lucide-react';
import { useAuth } from '../../hooks/useAuth';
import { getDefaultRouteForUser } from '../../utils/roles';
import type { AuthContextType } from '../../types/auth';
import './Login.css';

export function Login() {
  const auth = useAuth();
  return <AuthenticationScreen key={auth.stage} auth={auth} />;
}

function AuthenticationScreen({ auth }: { auth: AuthContextType }) {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [recover, setRecover] = useState(false);
  const [validation, setValidation] = useState<string | null>(null);
  useEffect(() => {
    if (auth.isAuthenticated) navigate(getDefaultRouteForUser(auth.user), { replace: true });
  }, [auth.isAuthenticated, auth.user, navigate]);

  const loginStage = ['login', 'session-ended'].includes(auth.stage);
  const enrollment = ['enrollment', 'replacement'].includes(auth.stage);
  const recovery = auth.stage === 'recovery';
  const headings: Partial<Record<typeof auth.stage, string>> = {
    mfa: 'Verify your authenticator', enrollment: 'Set up your authenticator',
    replacement: 'Replace your authenticator', recovery: 'Use a recovery code',
    'enrollment-unavailable': 'Enrollment unavailable',
    'recovery-codes': 'Save your recovery codes', 'session-ended': 'Sign in again',
  };
  async function submit(event: FormEvent) {
    event.preventDefault();
    setValidation(null);
    if (loginStage) {
      if (!email.trim() || !password) { setValidation('Enter your email and password.'); return; }
      const submitted = password;
      setPassword('');
      await auth.login(email.trim(), submitted, recover);
    } else {
      if (!code.trim() || (!recovery && !/^\d{6}$/.test(code.trim()))) {
        setValidation(recovery ? 'Enter one recovery code.' : 'Enter the six-digit authenticator code.');
        return;
      }
      const submitted = code.trim();
      setCode('');
      await auth.verify(submitted);
    }
  }
  let setup: URL | null = null;
  try { if (auth.provisioningUri) setup = new URL(auth.provisioningUri); } catch { /* no unsafe link */ }
  return <main className="gnosis-login-page">
    <section className="gnosis-visual-panel">
      <div className="gnosis-visual-overlay" />
      <div className="gnosis-visual-content">
        <div className="gnosis-logo"><div className="gnosis-logo-mark">G</div><div className="gnosis-logo-text"><span className="gnosis-logo-title">GNOSIS</span><span>MANAGEMENT SYSTEM</span></div></div>
        <div className="gnosis-visual-message"><h1>One secure place.</h1><p>Sign in with your password and authenticator to access your workspace.</p></div>
        <div className="gnosis-security-status"><ShieldCheck /><span>Multi-factor authentication required for every role</span></div>
      </div>
    </section>
    <section className="gnosis-auth-panel"><div className="gnosis-auth-container">
      <div className="gnosis-auth-heading"><span className="gnosis-auth-kicker">GNOSIS</span>
        <h2>{auth.isLoading ? 'Verifying your session...' : headings[auth.stage] || 'Sign in to GNOSIS'}</h2>
        <p>{enrollment ? 'Setup is complete only after the backend verifies a code from your new authenticator.' :
          recovery ? 'Your password has been checked. A single-use recovery code authorizes replacement setup, without application access.' :
          auth.stage === 'mfa' ? 'Enter a current code. Expired or reused codes cannot complete sign-in.' :
          loginStage ? 'Your password starts a restricted verification challenge.' : ''}</p>
      </div>
      {(auth.message || validation) && <div className="gnosis-error" role="alert">{validation || auth.message}</div>}
      {enrollment && !setup && <button type="button" className="gnosis-login-button" disabled={auth.busy} onClick={() => void auth.startEnrollment()}>
        {auth.busy ? 'Requesting setup...' : 'Request authenticator setup'}
      </button>}
      {setup && <section className="gnosis-mfa-material" aria-label="Authenticator setup">
        <p>In your authenticator, add an account manually using these settings. Keep this key private. It is shown only during this setup.</p>
        <dl><dt>Account</dt><dd>{decodeURIComponent(setup.pathname.slice(1))}</dd>
          <dt>Secret key</dt><dd><code>{setup.searchParams.get('secret')}</code></dd>
          <dt>Issuer</dt><dd>{setup.searchParams.get('issuer')}</dd>
          <dt>Algorithm / digits / interval</dt><dd>{setup.searchParams.get('algorithm') || 'SHA1'} / {setup.searchParams.get('digits') || '6'} / {setup.searchParams.get('period') || '30'} seconds</dd></dl>
      </section>}
      {!auth.isLoading && (loginStage || auth.stage === 'mfa' || recovery || (enrollment && setup)) && <form className="gnosis-form" onSubmit={submit}>
        {loginStage ? <>
          <div className="gnosis-field"><label htmlFor="email">Email address</label><div className="gnosis-input"><input id="email" type="email" autoComplete="username" required value={email} onChange={e => setEmail(e.target.value)} disabled={auth.busy} /></div></div>
          <div className="gnosis-field"><label htmlFor="password">Password</label><div className="gnosis-input"><Lock className="gnosis-input-icon" /><input id="password" type="password" autoComplete="current-password" required maxLength={1024} value={password} onChange={e => setPassword(e.target.value)} disabled={auth.busy} /></div></div>
          <label className="gnosis-recovery-choice"><input type="checkbox" checked={recover} onChange={e => setRecover(e.target.checked)} disabled={auth.busy} /> I need to replace my authenticator using a recovery code</label>
        </> : <div className="gnosis-field"><label htmlFor="verification-code">{recovery ? 'One recovery code' : 'Authenticator code'}</label><div className="gnosis-input"><input id="verification-code" type="text" inputMode={recovery ? 'text' : 'numeric'} autoComplete="off" spellCheck={false} maxLength={recovery ? 256 : 6} required value={code} onChange={e => setCode(e.target.value)} disabled={auth.busy} /></div></div>}
        <button className="gnosis-login-button" type="submit" disabled={auth.busy}>{auth.busy ? 'Verifying...' : loginStage ? 'Continue' : recovery ? 'Authorize replacement setup' : 'Verify authenticator'}</button>
      </form>}
      {auth.stage === 'recovery-codes' && <section className="gnosis-mfa-material">
        <p>Each code is a one-time credential. Save these securely offline. They cannot be retrieved again. Do not share them.</p>
        <ul aria-label="Recovery codes">{auth.recoveryCodes.map(value => <li key={value}><code>{value}</code></li>)}</ul>
        <button type="button" className="gnosis-login-button" disabled={auth.busy} onClick={auth.finishRecoveryCodes}>I have saved my codes - continue</button>
      </section>}
      {!auth.isLoading && !loginStage && auth.stage !== 'recovery-codes' && <button type="button" className="gnosis-auth-secondary" disabled={auth.busy} onClick={auth.restart}>Start again with your password</button>}
      {loginStage && <button type="button" className="gnosis-auth-secondary" disabled={auth.busy} onClick={() => void auth.logout()}>Sign out any existing session</button>}
      <p className="gnosis-auth-footer">No password-only access. Account setup and lost credentials require your organization's trusted recovery process.</p>
    </div></section>
  </main>;
}
