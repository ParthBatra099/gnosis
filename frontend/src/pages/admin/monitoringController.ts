import { securityApi } from '../../api/security';
import type { Query } from '../../api/security';
import { incidentsApi } from '../../api/incidents';
import { auditApi } from '../../api/audit';
import { onSessionRejected } from '../../api/client';
import type { Activity, Detection, Incident, IncidentDetail, MonitoringFilters, MonitoringMode, Overview, Page, Risk } from '../../types/security';

export interface MonitoringState {
  loading: boolean; busy: boolean; error: string; success: string; filters: MonitoringFilters;
  offset: number; overview: Overview | null; page: Page<Detection | Incident | Activity> | null;
  detail: IncidentDetail | null; risk: Risk | null;
}
export const initialFilters: MonitoringFilters = { employee_id: '', session_ref: '', category: '', severity: '', event_type: '', status: '', start: '', end: '' };
export function filterQuery(filters: MonitoringFilters): Query {
  const params: Query = {};
  for (const [key, value] of Object.entries(filters)) if (value.trim()) {
    if (key === 'start' || key === 'end') {
      const date = new Date(value);
      if (!Number.isFinite(date.getTime())) throw new Error('Enter valid dates.');
      params[key] = date.toISOString();
    } else params[key] = value.trim();
  }
  if (params.start && params.end && params.start >= params.end) throw new Error('Start must precede end.');
  return params;
}
export function monitoringError(error: unknown): string {
  const status = (error as { response?: { status?: number } })?.response?.status;
  if (status === 401) return 'Session expired. Sign in again.';
  if (status === 403 || status === 404) return 'This evidence is unavailable in your current authorized scope. Reload before continuing.';
  if (status === 400 || status === 409 || status === 422) return 'The operation was rejected. Review the dates, current incident status and required resolution notes.';
  return error instanceof Error && !status ? error.message : 'Security service unavailable. Retry explicitly.';
}
export const nextStatus: Record<string, string> = { OPEN: 'INVESTIGATING', INVESTIGATING: 'RESOLVED', RESOLVED: 'CLOSED' };

export class MonitoringController {
  readonly mode: MonitoringMode;
  private state: MonitoringState = { loading: false, busy: false, error: '', success: '', filters: { ...initialFilters }, offset: 0, overview: null, page: null, detail: null, risk: null };
  private listeners = new Set<() => void>();
  private generation = 0;
  private active = true;
  constructor(mode: MonitoringMode, category = '') { this.mode = mode; this.state.filters.category = category; }
  snapshot = () => this.state;
  subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private set(patch: Partial<MonitoringState>) { this.state = { ...this.state, ...patch }; this.listeners.forEach(fn => fn()); }
  connect() {
    this.active = true;
    const stop = onSessionRejected(() => { this.active = false; this.generation++; this.set({ overview: null, page: null, detail: null, risk: null, loading: false, busy: false, error: 'Session expired. Sign in again.' }); });
    return () => { stop(); this.active = false; this.generation++; };
  }
  async load(filters = this.state.filters, offset = this.state.offset) {
    if (!this.active) return;
    const generation = ++this.generation;
    this.set({ filters, offset, loading: true, busy: false, error: '', success: '', overview: null, page: null, detail: null, risk: null });
    try {
      const params = filterQuery(filters);
      if (this.mode === 'dashboard') {
        const overview = await securityApi.overview({ ...(params.start ? { start: params.start } : {}), ...(params.end ? { end: params.end } : {}) });
        if (this.active && generation === this.generation) this.set({ overview, loading: false });
      } else {
        const query: Query = { ...params, limit: 20, offset };
        if (this.mode === 'detections' && query.status) { query.incident_status = query.status; delete query.status; }
        const page = this.mode === 'detections' ? await securityApi.detections(query) : this.mode === 'incidents' ? await incidentsApi.list(query) : await auditApi.timeline(query);
        if (this.active && generation === this.generation) this.set({ page, loading: false });
        if (filters.employee_id && this.mode !== 'incidents') {
          const risks = await securityApi.employeeRisk(filters.employee_id.trim(), { ...(params.start ? { start: params.start } : {}), ...(params.end ? { end: params.end } : {}) });
          if (this.active && generation === this.generation) this.set({ risk: risks.latest });
        }
      }
    } catch (error) {
      if (this.active && generation === this.generation) this.set({ loading: false, page: null, overview: null, detail: null, risk: null, error: monitoringError(error) });
    }
  }
  async openIncident(id: string) {
    if (!this.active || this.state.busy) return;
    const generation = ++this.generation;
    this.set({ detail: null, busy: true, error: '', success: '' });
    try {
      const detail = await incidentsApi.detail(id);
      if (this.active && generation === this.generation) this.set({ detail, busy: false });
    } catch (error) {
      if (this.active && generation === this.generation) this.set({ busy: false, detail: null, page: null, error: monitoringError(error) });
    }
  }
  closeIncident() { this.generation++; this.set({ detail: null, busy: false }); }
  async updateIncident(status: string, notes: string, confirmed: boolean) {
    const detail = this.state.detail;
    if (!detail || this.state.busy || !this.active) return;
    if (!confirmed) { this.set({ error: 'Confirm the incident update before submitting.' }); return; }
    if (status && nextStatus[detail.status] !== status) { this.set({ error: 'Reload and select the next supported status.' }); return; }
    if (status === 'RESOLVED' && !(notes.trim() || detail.resolution_notes)) { this.set({ error: 'Resolution notes are required.' }); return; }
    const generation = ++this.generation;
    this.set({ busy: true, error: '', success: '' });
    try {
      await incidentsApi.update(detail.id, { ...(status ? { status } : {}), resolution_notes: notes.trim() || null });
      if (!this.active || generation !== this.generation) return;
      await this.load();
      if (!this.active) return;
      await this.openIncident(detail.id);
      if (this.active && this.state.detail) this.set({ success: 'Incident updated from the backend. Review the recorded history.' });
      else if (this.active) this.set({ error: 'The update was accepted, but refreshed incident details are unavailable. Reload to verify the current state.' });
    } catch (error) {
      if (this.active && generation === this.generation) this.set({ busy: false, detail: null, page: null, error: monitoringError(error) });
    }
  }
}
