import { useEffect, useState, useSyncExternalStore } from 'react';
import type { ReactNode } from 'react';
import { AuthContext } from '../context/AuthContext';
import { DemoController } from './controller';

const unsupportedMfa = async () => { throw new Error('MFA workflows are available only in normal GNOSIS.'); };
export function DemoProvider({ children }: { children: ReactNode }) {
  const [controller] = useState(() => new DemoController());
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot);
  useEffect(() => {
    const disconnect = controller.connect();
    void controller.restore();
    const refresh = () => { if (document.visibilityState === 'visible') void controller.refresh(); };
    window.addEventListener('focus', refresh);
    document.addEventListener('visibilitychange', refresh);
    return () => { disconnect(); window.removeEventListener('focus', refresh); document.removeEventListener('visibilitychange', refresh); };
  }, [controller]);
  return <AuthContext.Provider value={{ ...state,
    isAuthenticated: state.stage === 'authenticated' && state.user !== null,
    isLoading: state.stage === 'restoring', login: controller.login, logout: controller.logout,
    restart: controller.restart, verify: unsupportedMfa, startEnrollment: unsupportedMfa,
    finishRecoveryCodes: () => { /* Demo never issues recovery codes. */ },
  }}>{children}</AuthContext.Provider>;
}
