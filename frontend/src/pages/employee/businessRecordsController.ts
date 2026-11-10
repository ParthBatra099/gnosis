import { getBusinessRecords, getResourceMetadata } from '../../api/resources';
import type { BusinessRecordsResponse, ResourceMetadata } from '../../api/resources';
import { onSessionRejected } from '../../api/client';

export interface BusinessRecordsState {
  resources: ResourceMetadata[];
  selectedId: string;
  limit: number;
  offset: number;
  response: BusinessRecordsResponse | null;
  loadingMetadata: boolean;
  busy: boolean;
  error: string;
  outcome: 'idle' | 'allowed' | 'denied' | 'error' | 'session-ended';
}
const empty = (): BusinessRecordsState => ({ resources: [], selectedId: '', limit: 25, offset: 0,
  response: null, loadingMetadata: false, busy: false, error: '', outcome: 'idle' });
const code = (error: unknown) => (error as { response?: { status?: number } })?.response?.status;
export function businessRecordsError(error: unknown): string {
  switch (code(error)) {
    case 401: return 'Your session ended or was revoked. Sign in again.';
    case 403: return 'Access denied by backend security policy. No business records were returned.';
    case 404: return 'This resource is unavailable. Refresh the resource list before trying again.';
    case 422: return 'The backend rejected the pagination. Choose a page size from 1 to 100 and a non-negative offset.';
    case 503: return 'Record retrieval or disclosure capture is unavailable. No successful disclosure response was received. Retry only by explicit request.';
    default: return 'The request could not be completed or validated. Records are not shown; the server may already have processed the request. Retry only by explicit request.';
  }
}

export class BusinessRecordsController {
  private state = empty();
  private revision = 0;
  private active = true;
  private listeners = new Set<() => void>();
  private api: { metadata: typeof getResourceMetadata; records: typeof getBusinessRecords };
  constructor(api = { metadata: getResourceMetadata, records: getBusinessRecords }) { this.api = api; }
  snapshot = () => this.state;
  subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private publish(patch: Partial<BusinessRecordsState>) { this.state = { ...this.state, ...patch }; this.listeners.forEach(fn => fn()); }
  connect = () => {
    this.active = true;
    const stop = onSessionRejected(this.sessionEnded);
    return () => { stop(); this.active = false; this.revision++; this.state = empty(); };
  };
  private sessionEnded = () => {
    this.active = false;
    this.revision++;
    this.publish({ ...empty(), outcome: 'session-ended', error: 'Your session ended or is unavailable. Sign in again.' });
  };
  loadMetadata = async () => {
    if (!this.active) return;
    const revision = ++this.revision;
    this.publish({ ...empty(), loadingMetadata: true });
    try {
      const resources = await this.api.metadata();
      if (this.active && revision === this.revision) this.publish({ resources, loadingMetadata: false });
    } catch (error) {
      if (!this.active || revision !== this.revision) return;
      if (code(error) === 401) { this.sessionEnded(); return; }
      this.publish({ loadingMetadata: false, error: 'Resource metadata is unavailable. Refresh explicitly to try again.', outcome: 'error' });
    }
  };
  select = (id: string) => {
    if (!this.active) return;
    this.revision++;
    const selectedId = this.state.resources.some(resource => resource.id === id) ? id : '';
    this.publish({ selectedId, offset: 0, response: null, busy: false, error: '', outcome: 'idle' });
  };
  setLimit = (limit: number) => {
    if (!this.active) return;
    this.revision++;
    const valid = Number.isSafeInteger(limit) && limit >= 1 && limit <= 100;
    this.publish({ ...(valid ? { limit } : {}), offset: 0, response: null, busy: false,
      error: valid ? '' : 'Choose a page size from 1 to 100.', outcome: valid ? 'idle' : 'error' });
  };
  // Only buttons/form submissions call this method. Selection, mount and focus do not.
  request = async (offset = this.state.offset) => {
    if (!this.active || this.state.busy || this.state.loadingMetadata) return;
    const revision = ++this.revision;
    const { selectedId, limit } = this.state;
    this.publish({ response: null, error: '', outcome: 'idle' });
    if (!selectedId || !Number.isSafeInteger(offset) || offset < 0) {
      this.publish({ error: selectedId ? 'Choose a non-negative page offset.' : 'Select a resource first.', outcome: 'error' });
      return;
    }
    this.publish({ busy: true, offset });
    try {
      const response = await this.api.records(selectedId, limit, offset);
      if (this.active && revision === this.revision) this.publish({ response, busy: false, outcome: 'allowed' });
    } catch (error) {
      if (!this.active || revision !== this.revision) return;
      if (code(error) === 401) { this.sessionEnded(); return; }
      this.publish({ response: null, busy: false, error: businessRecordsError(error), outcome: code(error) === 403 ? 'denied' : 'error' });
    }
  };
}

export function connectBusinessRecords(controller: BusinessRecordsController) {
  const disconnect = controller.connect();
  void controller.loadMetadata();
  return disconnect;
}
