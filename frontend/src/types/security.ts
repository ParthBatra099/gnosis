export interface Page<T> { items: T[]; total: number; limit: number; offset: number }
export interface Detection {
  id: string; event_type: string; severity: string; actor_id: string | null;
  resource_id: string | null; timestamp: string; description: string;
  evidence: Record<string, unknown> | null; related_incidents?: { id: string; status: string }[];
}
export interface Risk {
  id: string; actor_id: string; scope: string; scope_key: string; score: number; level: string;
  policy_version: string; timestamp: string; window_start: string; window_end: string;
  factors: { factor: string; contribution: number; explanation: string; active: boolean }[];
  evidence: Record<string, unknown>;
}
export interface Incident {
  id: string; title: string; description: string; severity: string; status: string;
  reporter_id: string | null; assigned_to_id: string | null; resource_id: string | null;
  created_at: string; updated_at: string; resolution_notes: string | null;
}
export interface IncidentDetail extends Incident {
  detection_evidence: Detection[];
  history: { id: string; timestamp: string; actor_id: string; action: string; status: string | null }[];
}
export interface Activity {
  id: string; source: string; source_id: string; timestamp: string; category: string;
  actor_id: string | null; resource_id: string | null; department_ids: string[];
  severity: string | null; outcome: string | null; explanation: string; sensitivity: string | null;
  record_id: string | null; session_ref: string | null; incident_id: string | null;
  transport_state: string | null; status: string | null;
  related_incidents: { id: string; status: string }[];
  details?: Record<string, unknown> | null;
}
export interface Overview {
  start: string; end: string; detections: number; high_detections: number; critical_detections: number;
  elevated_employees: number; open_incidents: number; investigating_incidents: number;
  resolved_incidents: number; closed_incidents: number; disclosure_events: number; distinct_records: number;
  recent_detections: Detection[]; employee_risks: Risk[]; recent_activity: Activity[];
}
export type MonitoringMode = 'dashboard' | 'detections' | 'incidents' | 'timeline';
export interface MonitoringFilters {
  employee_id: string; session_ref: string; category: string; severity: string;
  event_type: string; status: string; start: string; end: string;
}
