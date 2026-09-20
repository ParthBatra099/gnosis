import React, { useState, useEffect } from 'react';
import type { FormEvent, ChangeEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Lock, Mail, AlertCircle, Loader2 } from 'lucide-react';
import { useAuth } from '../../hooks/useAuth';
import { getDefaultRouteForUser } from '../../utils/roles';

export const Login: React.FC = () => {
  const { login, user, isAuthenticated, isLoading: isAuthLoading } = useAuth();
  const navigate = useNavigate();

  const [email, setEmail] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);

  // Automatically redirect if session is already authenticated
  useEffect(() => {
    if (isAuthenticated && user) {
      navigate(getDefaultRouteForUser(user), { replace: true });
    }
  }, [isAuthenticated, user, navigate]);

  const handleEmailChange = (e: ChangeEvent<HTMLInputElement>) => {
    setEmail(e.target.value);
    if (errorMessage) setErrorMessage(null);
  };

  const handlePasswordChange = (e: ChangeEvent<HTMLInputElement>) => {
    setPassword(e.target.value);
    if (errorMessage) setErrorMessage(null);
  };

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
        const response = (err as { response?: { status?: number } }).response;
        if (response?.status === 401) {
          setErrorMessage('Invalid email or password.');
        } else {
          setErrorMessage('Security authentication service error. Please try again.');
        }
      } else if (err && typeof err === 'object' && 'request' in err) {
        setErrorMessage('Unable to connect to GNOSIS security service. Check network connection.');
      } else {
        setErrorMessage('An unexpected authentication error occurred.');
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  if (isAuthLoading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 animate-pulse">
            <Shield className="w-6 h-6" />
          </div>
          <p className="text-xs font-mono text-slate-400 tracking-wider uppercase">
            Verifying Session...
          </p>
        </div>
      </div>
    );
  }

  const isFormDisabled = isSubmitting || isAuthLoading;

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col justify-center items-center p-4 relative overflow-hidden select-none">
      {/* Background Decorative Glows */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-1/4 left-1/2 -translate-x-1/2 translate-y-1/2 w-96 h-96 bg-blue-600/10 rounded-full blur-3xl pointer-events-none" />

      {/* Login Container */}
      <div className="w-full max-w-md bg-slate-900/90 backdrop-blur-xl border border-slate-800 rounded-2xl p-8 shadow-2xl relative z-10 space-y-8">
        {/* Brand Header */}
        <div className="text-center space-y-3">
          <div className="inline-flex w-14 h-14 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 items-center justify-center text-cyan-400 shadow-[0_0_25px_rgba(6,182,212,0.2)] mb-1">
            <Shield className="w-7 h-7" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-wider text-slate-100 font-mono">
              GNOSIS
            </h1>
            <p className="text-xs font-semibold text-cyan-400 tracking-widest uppercase mt-0.5">
              Enterprise Data Security Platform
            </p>
          </div>
          <p className="text-xs text-slate-400 max-w-xs mx-auto leading-relaxed">
            Secure authentication for your organization&apos;s data security console.
          </p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-5" noValidate>
          {/* Error Message */}
          {errorMessage && (
            <div
              role="alert"
              className="flex items-center gap-3 p-3.5 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 text-xs font-medium animate-fadeIn"
            >
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{errorMessage}</span>
            </div>
          )}

          {/* Email Input */}
          <div className="space-y-1.5">
            <label
              htmlFor="email"
              className="block text-xs font-medium text-slate-300 font-mono"
            >
              Email Address
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                <Mail className="w-4 h-4" />
              </div>
              <input
                id="email"
                type="email"
                required
                autoComplete="email"
                value={email}
                onChange={handleEmailChange}
                placeholder="user@organization.com"
                disabled={isFormDisabled}
                className="w-full pl-10 pr-4 py-2.5 bg-slate-950/70 border border-slate-800 focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/30 rounded-xl text-xs text-slate-100 placeholder-slate-600 transition-all duration-150 outline-none disabled:opacity-50"
              />
            </div>
          </div>

          {/* Password Input */}
          <div className="space-y-1.5">
            <label
              htmlFor="password"
              className="block text-xs font-medium text-slate-300 font-mono"
            >
              Password
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                <Lock className="w-4 h-4" />
              </div>
              <input
                id="password"
                type="password"
                required
                autoComplete="current-password"
                value={password}
                onChange={handlePasswordChange}
                placeholder="••••••••••••"
                disabled={isFormDisabled}
                className="w-full pl-10 pr-4 py-2.5 bg-slate-950/70 border border-slate-800 focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/30 rounded-xl text-xs text-slate-100 placeholder-slate-600 transition-all duration-150 outline-none disabled:opacity-50"
              />
            </div>
          </div>

          {/* Submit Button */}
          <button
            type="submit"
            disabled={isFormDisabled}
            className="w-full py-3 px-4 bg-cyan-500 hover:bg-cyan-400 active:bg-cyan-600 text-slate-950 font-semibold text-xs rounded-xl shadow-[0_0_20px_rgba(6,182,212,0.25)] hover:shadow-[0_0_25px_rgba(6,182,212,0.4)] transition-all duration-150 flex items-center justify-center gap-2 cursor-pointer disabled:opacity-60 disabled:cursor-not-allowed font-mono uppercase tracking-wider"
          >
            {isSubmitting ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>AUTHENTICATING...</span>
              </>
            ) : (
              <span>Sign In</span>
            )}
          </button>
        </form>

        {/* Footer */}
        <div className="pt-2 border-t border-slate-800/80 text-center">
          <p className="text-[11px] text-slate-500 font-mono">
            GNOSIS Security Engine &bull; Protected Access Domain
          </p>
        </div>
      </div>
    </div>
  );
};