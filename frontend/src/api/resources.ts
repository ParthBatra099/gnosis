import { apiClient } from './client';

export interface ResourceMetadata {
  id: string;
  name: string;
  description?: string | null;
  department_id?: string | null;
  sensitivity?: string | null;
}

export async function getResourceMetadata(): Promise<ResourceMetadata[]> {
  const response = await apiClient.get<ResourceMetadata[]>(
    '/access/resources/metadata'
  );

  return response.data;
}

export interface BusinessRecord {
  id: string;
  category: string;
  sensitivity: string;
  values: Record<string, unknown>;
}
export interface BusinessRecordsResponse {
  response_id: string;
  resource_id: string;
  records: BusinessRecord[];
  disclosure_semantics: string;
}
export async function getBusinessRecords(resourceId: string, limit = 25, offset = 0): Promise<BusinessRecordsResponse> {
  if (!resourceId || !Number.isSafeInteger(limit) || limit < 1 || limit > 100 ||
      !Number.isSafeInteger(offset) || offset < 0) throw new Error('Invalid record pagination.');
  const response = await apiClient.get<BusinessRecordsResponse>(
    '/resources/' + encodeURIComponent(resourceId) + '/records', { params: { limit, offset } });
  const data = response.data;
  if (!data || data.resource_id !== resourceId || typeof data.response_id !== 'string' || !data.response_id ||
      typeof data.disclosure_semantics !== 'string' || !Array.isArray(data.records) || data.records.length > limit ||
      data.records.some(record => !record || typeof record.id !== 'string' || typeof record.category !== 'string' ||
        typeof record.sensitivity !== 'string' || !record.values || typeof record.values !== 'object' || Array.isArray(record.values)))
    throw new Error('The record response could not be validated. Data is not shown; the server may already have processed this request.');
  return data;
}
