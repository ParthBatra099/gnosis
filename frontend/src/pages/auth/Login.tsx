import React, { useState, useEffect } from 'react';
import type { FormEvent, ChangeEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Lock,
  Mail,
  AlertCircle,
  Loader2,
  ArrowRight,
  ShieldCheck,
} from 'lucide-react';

import { useAuth } from '../../hooks/useAuth';
import { getDefaultRouteForUser } from '../../utils/roles';

import './Login.css';

export const Login: React.FC = () => {
  const { login, user, isAuthenticated, isLoading: isAuthLoading } =
    useAuth();

  const navigate = useNavigate();

  const [email, setEmail] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [rememberMe, setRememberMe] = useState<boolean>(false);

  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);

  /*
   * Redirect authenticated users
   */
  useEffect(() => {
    if (isAuthenticated && user) {
      navigate(getDefaultRouteForUser(user), { replace: true });
    }
  }, [isAuthenticated, user, navigate]);

  /*
   * Email change
   */
  const handleEmailChange = (e: ChangeEvent<HTMLInputElement>) => {
    setEmail(e.target.value);

    if (errorMessage) {
      setErrorMessage(null);
    }
  };

  /*
   * Password change
   */
  const handlePasswordChange = (e: ChangeEvent<HTMLInputElement>) => {
    setPassword(e.target.value);

    if (errorMessage) {
      setErrorMessage(null);
    }
  };

  /*
   * Login
   */
  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();

    if (!email.trim() || !password) {
      setErrorMessage('Please provide both email and password.');
      return;
    }

    setErrorMessage(null);
    setIsSubmitting(true);

    try {
      await login(email, password);
    } catch (err: unknown) {
      if (err && typeof err === 'object' && 'response' in err) {
        const response = (
          err as { response?: { status?: number } }
        ).response;

        if (response?.status === 401) {
          setErrorMessage('Invalid email or password.');
        } else {
          setErrorMessage(
            'Security authentication service error. Please try again.'
          );
        }
      } else if (err && typeof err === 'object' && 'request' in err) {
        setErrorMessage(
          'Unable to connect to GNOSIS security service. Check network connection.'
        );
      } else {
        setErrorMessage('An unexpected authentication error occurred.');
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  /*
   * Authentication loading state
   */
  if (isAuthLoading) {
    return (
      <div className="gnosis-loading">
        <div className="gnosis-loading-card">
          <div className="gnosis-loading-logo">G</div>

          <div className="gnosis-loading-spinner">
            <Loader2 />
          </div>

          <p>Verifying your session...</p>
        </div>
      </div>
    );
  }

  const isFormDisabled = isSubmitting || isAuthLoading;

  return (
    <main className="gnosis-login-page">

      {/* =========================================
          LEFT VISUAL PANEL
      ========================================== */}

      <section className="gnosis-visual-panel">

        <div className="gnosis-visual-overlay" />

        <div className="gnosis-visual-content">

          {/* Logo */}
          <div className="gnosis-logo">
            <div className="gnosis-logo-mark">
              G
            </div>

            <div className="gnosis-logo-text">
              <span className="gnosis-logo-title">
                GNOSIS
              </span>

              <span className="gnosis-logo-subtitle">
                MANAGEMENT SYSTEM
              </span>
            </div>
          </div>

          {/* Main visual message */}
          <div className="gnosis-visual-message">

            <span className="gnosis-eyebrow">
              SECURE. INTELLIGENT. CONNECTED.
            </span>

            <h1>
              Everything you need.
              <br />
              <span>One secure place.</span>
            </h1>

            <p>
              Manage resources, access requests and organizational
              security through one intelligent management system.
            </p>

          </div>

          {/* Security indicator */}
          <div className="gnosis-security-status">

            <div className="gnosis-security-icon">
              <ShieldCheck />
            </div>

            <div>
              <strong>GNOSIS Security</strong>
              <span>Protected environment</span>
            </div>

            <div className="gnosis-status-dot" />

          </div>

        </div>

      </section>


      {/* =========================================
          RIGHT AUTH PANEL
      ========================================== */}

      <section className="gnosis-auth-panel">

        <div className="gnosis-auth-container">

          {/* Mobile logo */}
          <div className="gnosis-mobile-logo">
            <div className="gnosis-logo-mark">
              G
            </div>

            <span>GNOSIS</span>
          </div>


          {/* Heading */}
          <div className="gnosis-auth-heading">

            <span className="gnosis-auth-kicker">
              WELCOME BACK
            </span>

            <h2>
              Sign in to
              <br />
              <span>GNOSIS.</span>
            </h2>

            <p>
              Access your workspace and manage your organization's
              resources securely.
            </p>

          </div>


          {/* Error */}
          {errorMessage && (
            <div
              className="gnosis-error"
              role="alert"
            >
              <AlertCircle />

              <span>
                {errorMessage}
              </span>
            </div>
          )}


          {/* Login Form */}
          <form
            onSubmit={handleSubmit}
            className="gnosis-form"
            noValidate
          >

            {/* Email */}
            <div className="gnosis-field">

              <label htmlFor="email">
                Email address
              </label>

              <div className="gnosis-input">

                <Mail className="gnosis-input-icon" />

                <input
                  id="email"
                  type="email"
                  required
                  autoComplete="email"
                  value={email}
                  onChange={handleEmailChange}
                  placeholder="you@company.com"
                  disabled={isFormDisabled}
                />

              </div>

            </div>


            {/* Password */}
            <div className="gnosis-field">

              <div className="gnosis-field-header">

                <label htmlFor="password">
                  Password
                </label>

                <button
                  type="button"
                  className="gnosis-forgot"
                  onClick={() =>
                    setErrorMessage(
                      'Please contact your administrator to reset your password.'
                    )
                  }
                >
                  Forgot password?
                </button>

              </div>

              <div className="gnosis-input">

                <Lock className="gnosis-input-icon" />

                <input
                  id="password"
                  type="password"
                  required
                  autoComplete="current-password"
                  value={password}
                  onChange={handlePasswordChange}
                  placeholder="Enter your password"
                  disabled={isFormDisabled}
                />

              </div>

            </div>


            {/* Remember me */}
            <label className="gnosis-remember">

              <input
                type="checkbox"
                checked={rememberMe}
                onChange={(e) =>
                  setRememberMe(e.target.checked)
                }
                disabled={isFormDisabled}
              />

              <span className="gnosis-checkbox">
                <span />
              </span>

              <span className="gnosis-remember-text">
                Keep me signed in
              </span>

            </label>


            {/* Login button */}
            <button
              type="submit"
              disabled={isFormDisabled}
              className="gnosis-login-button"
            >

              {isSubmitting ? (
                <>
                  <Loader2 className="gnosis-spinner" />

                  <span>
                    Authenticating...
                  </span>
                </>
              ) : (
                <>
                  <span>
                    Sign in to GNOSIS
                  </span>

                  <span className="gnosis-button-arrow">
                    <ArrowRight />
                  </span>
                </>
              )}

            </button>

          </form>


          {/* Footer */}
          <div className="gnosis-auth-footer">

            <span>
              Authorized personnel only
            </span>

            <span className="gnosis-footer-divider">
              •
            </span>

            <span>
              Secure access
            </span>

          </div>

        </div>

      </section>

    </main>
  );
};