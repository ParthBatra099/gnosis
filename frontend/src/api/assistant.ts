import axios from 'axios';
import { apiClient } from './client';
import type {
  AssistantQueryRequest,
  AssistantQueryResponse,
} from '../types/assistant';

export async function askGnosis(query: string): Promise<AssistantQueryResponse> {
  const body: AssistantQueryRequest = { query };
  const response = await apiClient.post<AssistantQueryResponse>(
    '/assistant/query',
    body
  );
  return response.data;
}

export function isUnauthorizedError(error: unknown): boolean {
  return axios.isAxiosError(error) && error.response?.status === 401;
}