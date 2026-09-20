import { useState, useEffect, useCallback } from 'react';
import type { ReactNode } from 'react';
import { AuthContext } from './AuthContext';
import type { AuthContextType } from '../types/auth';
import type { UserResponse } from '../types/api';
import { login as loginApi, getCurrentUser } from '../api/auth';
import { AUTH_TOKEN_KEY } from '../utils/constants';

interface AuthProviderProps {
  children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<UserResponse | null>(null);
  const [token, setToken] = useState<string | null>(() =>
    localStorage.getItem(AUTH_TOKEN_KEY)
  );
  const [isLoading, setIsLoading] = useState<boolean>(true);

  useEffect(() => {
    async function initializeAuth() {
      const storedToken = localStorage.getItem(AUTH_TOKEN_KEY);

      if (!storedToken) {
        setUser(null);
        setToken(null);
        setIsLoading(false);
        return;
      }

      try {
        const currentUser = await getCurrentUser();
        setUser(currentUser);
        setToken(storedToken);
      } catch {
        localStorage.removeItem(AUTH_TOKEN_KEY);
        setUser(null);
        setToken(null);
      } finally {
        setIsLoading(false);
      }
    }

    initializeAuth();
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    setIsLoading(true);
    try {
      const tokenData = await loginApi(email, password);
      localStorage.setItem(AUTH_TOKEN_KEY, tokenData.access_token);
      setToken(tokenData.access_token);

      const currentUser = await getCurrentUser();
      setUser(currentUser);
    } catch (error) {
      localStorage.removeItem(AUTH_TOKEN_KEY);
      setToken(null);
      setUser(null);
      throw error;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem(AUTH_TOKEN_KEY);
    setToken(null);
    setUser(null);
  }, []);

  const value: AuthContextType = {
    user,
    token,
    isAuthenticated: Boolean(user && token),
    isLoading,
    login,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}