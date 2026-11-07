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