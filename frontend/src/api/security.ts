import { apiClient } from './client';
import type { Detection, Overview, Page, Risk } from '../types/security';
export type Query = Record<string, string | number>;
export const securityApi = {
  overview: async (params: Query) => (await apiClient.get<Overview>('/console/dashboard/security-overview', { params })).data,
  detections: async (params: Query) => (await apiClient.get<Page<Detection>>('/monitoring/detections', { params })).data,
  risks: async (params: Query) => (await apiClient.get<Page<Risk>>('/monitoring/risk-assessments', { params })).data,
  employeeRisk: async (id: string, params: Query) => (await apiClient.get<Page<Risk> & { latest: Risk | null }>('/monitoring/risk/employees/' + encodeURIComponent(id), { params })).data,
};
