import { apiClient } from './client';
import type { Incident, IncidentDetail, Page } from '../types/security';
import type { Query } from './security';
export const incidentsApi = {
  list: async (params: Query) => (await apiClient.get<Page<Incident>>('/console/incidents/page', { params })).data,
  detail: async (id: string) => (await apiClient.get<IncidentDetail>('/console/incidents/' + encodeURIComponent(id))).data,
  update: async (id: string, payload: { status?: string; resolution_notes?: string | null }) =>
    (await apiClient.patch<Incident>('/console/incidents/' + encodeURIComponent(id), payload)).data,
};
