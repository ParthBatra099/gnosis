import { apiClient } from './client';

export interface AccessRequest {
  id: string;
  requester_id: string;
  resource_id: string;
  permission: string;
  reason: string;
  status: string;
  created_at: string;
}

export interface CreateAccessRequestPayload {
  resource_id: string;
  permission: string;
  reason: string;
}

export async function createAccessRequest(
  payload: CreateAccessRequestPayload
): Promise<AccessRequest> {
  const response = await apiClient.post<AccessRequest>(
    '/access/requests',
    payload
  );

  return response.data;
}

export async function getMyAccessRequests(): Promise<AccessRequest[]> {
  const response = await apiClient.get<AccessRequest[]>(
    '/access/requests/me'
  );

  return response.data;
}

export async function getPendingAccessRequests(): Promise<AccessRequest[]> {
  const response = await apiClient.get<AccessRequest[]>(
    '/access/requests/pending-approvals'
  );

  return response.data;
}

export async function approveAccessRequest(
  requestId: string
): Promise<unknown> {
  const response = await apiClient.post(
    `/access/requests/${requestId}/approve`
  );

  return response.data;
}

export async function rejectAccessRequest(
  requestId: string
): Promise<AccessRequest> {
  const response = await apiClient.post<AccessRequest>(
    `/access/requests/${requestId}/reject`
  );

  return response.data;
}