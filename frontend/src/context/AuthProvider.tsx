import { useEffect, useState, useSyncExternalStore } from 'react';
import type { ReactNode } from 'react';
import { AuthContext } from './AuthContext';
import { AuthController } from './authController';
import type { AuthContextType } from '../types/auth';

export function AuthProvider({ children }: { children: ReactNode }) {
  const [controller] = useState(() => new AuthController());
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot);
  useEffect(() => {
    // Remove the obsolete bearer value without reading or using it.
    try { localStorage.removeItem('gnosis_auth_token'); } catch { /* Cookie auth does not require storage access. */ }
    const disconnect = controller.connect();
    void controller.restore();
    const refresh = () => { if (document.visibilityState === 'visible') void controller.refresh(); };
    window.addEventListener('focus', refresh);
    document.addEventListener('visibilitychange', refresh);
    return () => {
      disconnect();
      window.removeEventListener('focus', refresh);
      document.removeEventListener('visibilitychange', refresh);
    };
  }, [controller]);
  const value: AuthContextType = {
    ...state,
    isAuthenticated: state.stage === 'authenticated' && state.user !== null,
    isLoading: state.stage === 'restoring',
    login: controller.login, verify: controller.verify,
    startEnrollment: controller.startEnrollment, finishRecoveryCodes: controller.finishRecoveryCodes,
    restart: controller.restart, logout: controller.logout,
  };
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
