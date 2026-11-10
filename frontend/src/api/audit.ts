import { apiClient } from './client';
import type { Activity, Page } from '../types/security';
import type { Query } from './security';
export const auditApi = {
  timeline: async (params: Query) => (await apiClient.get<Page<Activity>>('/monitoring/timeline', { params })).data,
};
