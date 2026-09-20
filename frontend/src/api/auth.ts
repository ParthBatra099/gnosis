import { apiClient } from './client';
import type { LoginRequest, TokenResponse } from '../types/auth';
import type { UserResponse } from '../types/api';

export async function login(
  email: string,
  password: string
): Promise<TokenResponse> {
  const payload: LoginRequest = { email, password };
  const response = await apiClient.post<TokenResponse>('/auth/login', payload);
  return response.data;
}

export async function getCurrentUser(): Promise<UserResponse> {
  const response = await apiClient.get<UserResponse>('/auth/me');
  return response.data;
}