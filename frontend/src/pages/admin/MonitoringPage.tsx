import { useEffect, useState, useSyncExternalStore } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';
import { isAdministrator } from '../../utils/roles';
import { MonitoringController, nextStatus } from './monitoringController';
import type { MonitoringState } from './monitoringController';
import type { Activity, Detection, Incident, MonitoringFilters, MonitoringMode, Overview, Risk } from '../../types/security';
import './MonitoringPage.css';

const categories = ['ACCESS_ALLOWED', 'ACCESS_DENIED', 'DATA_DISCLOSED', 'SECURITY_DETECTION', 'RISK_ASSESSMENT', 'INCIDENT_CREATED', 'INCIDENT_UPDATED', 'AUDIT_EVENT'];
const titles = { dashboard: 'Security overview', detections: 'Security events & alerts', incidents: 'Incident management', timeline: 'Security activity timeline' };
const formatTime = (value: string) => new Date(value).toLocaleString();
export function Severity({ value }: { value: string | null }) {
  return <span className={'monitor-badge ' + (value || 'UNKNOWN').toLowerCase()}>{value || '—'}</span>;
}
export function Evidence({ value }: { value: unknown }) {
  return <details><summary>Recorded evidence</summary><pre>{JSON.stringify(value, null, 2)}</pre></details>;
}
export function RiskCard({ risk }: { risk: Risk }) {
  return <article className="monitor-card"><h3>Employee <code>{risk.actor_id}</code></h3>
    <p><Severity value={risk.level} /> <strong>{risk.score}/100</strong> · {formatTime(risk.timestamp)}</p>
    <p>Observational review indicator, not a probability of malicious behaviour or an access decision.</p>
    <p>Policy {risk.policy_version} · {risk.scope} · {formatTime(risk.window_start)} – {formatTime(risk.window_end)}</p>
    <ul>{risk.factors.filter(f => f.active).map(f => <li key={f.factor}>{f.explanation} (+{f.contribution})</li>)}</ul>
    {!risk.factors.some(f => f.active) && <p>No contributing factors in the recorded evidence. This does not establish safety.</p>}
    <Evidence value={risk.evidence} /><Link to={'/admin/timeline?employee_id=' + encodeURIComponent(risk.actor_id)}>Review employee timeline</Link>
  </article>;
}

export function MonitoringPage({ mode, category = '' }: { mode: MonitoringMode; category?: string }) {
  const { user } = useAuth();
  if (!isAdministrator(user)) return <p>Administrative monitoring unavailable for this canonical role.</p>;
  return <ConnectedMonitoring key={mode + user?.id + user?.organization_role} mode={mode} category={category} />;
}
function ConnectedMonitoring({ mode, category }: { mode: MonitoringMode; category: string }) {
  const { search } = useLocation();
  const [controller] = useState(() => new MonitoringController(mode, category));
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot);
  useEffect(() => {
    const disconnect = controller.connect();
    const params = new URLSearchParams(search);
    const filters = { ...controller.snapshot().filters, employee_id: params.get('employee_id') || '', session_ref: params.get('session_ref') || '' };
    const incident = params.get('incident_id');
    void controller.load(filters, 0).then(() => { if (incident) return controller.openIncident(incident); });
    return disconnect;
  }, [controller, search]);
  return <MonitoringView controller={controller} state={state} />;
}

function Filters({ controller, state }: { controller: MonitoringController; state: MonitoringState }) {
  const [draft, setDraft] = useState<MonitoringFilters>(state.filters);
  const mode = controller.mode;
  const input = (key: keyof MonitoringFilters, label: string, type = 'text') => <label>{label}<input type={type} value={draft[key]} onChange={e => setDraft({ ...draft, [key]: e.target.value })} /></label>;
  const select = (key: keyof MonitoringFilters, label: string, values: string[]) => <label>{label}<select value={draft[key]} onChange={e => setDraft({ ...draft, [key]: e.target.value })}><option value="">All</option>{values.map(v => <option key={v} value={v}>{v.replaceAll('_', ' ')}</option>)}</select></label>;
  return <form className="monitor-filters" onSubmit={e => { e.preventDefault(); void controller.load(draft, 0); }}>
    {mode !== 'dashboard' && mode !== 'incidents' && input('employee_id', 'Employee ID')}
    {mode === 'timeline' && input('session_ref', 'Session fingerprint')}
    {mode !== 'dashboard' && select('severity', 'Severity / risk level', ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])}
    {mode === 'timeline' && select('category', 'Activity category', categories)}
    {mode === 'detections' && input('event_type', 'Detection / rule identifier')}
    {(mode === 'incidents' || mode === 'detections') && select('status', 'Incident status', ['OPEN', 'INVESTIGATING', 'RESOLVED', 'CLOSED'])}
    {input('start', 'From (local time)', 'datetime-local')}{input('end', 'Until (exclusive)', 'datetime-local')}
    <button disabled={state.loading || state.busy} type="submit">Apply filters</button>
  </form>;
}

export function MonitoringView({ controller, state }: { controller: MonitoringController; state: MonitoringState }) {
  const mode = controller.mode;
  return <section className="monitor-page" aria-busy={state.loading || state.busy}>
    <header className="monitor-heading"><div><p className="monitor-eyebrow">GNOSIS SECURITY CONSOLE</p><h1>{titles[mode]}</h1>
      <p>Persisted evidence in your current authorized scope. Risk never changes permissions.</p></div>
      <button disabled={state.loading || state.busy} onClick={() => void controller.load()}>Reload current data</button></header>
    <nav className="monitor-nav" aria-label="Security monitoring"><Link to="/admin">Overview</Link><Link to="/admin/security-events">Detections</Link><Link to="/admin/incidents">Incidents</Link><Link to="/admin/timeline">Activity timeline</Link><Link to="/admin/audit-logs">Other audit activity</Link></nav>
    <Filters key={JSON.stringify(state.filters)} controller={controller} state={state} />
    {state.error && <p role="alert" className="monitor-error">{state.error}</p>}
    {state.success && <p role="status" className="monitor-success">{state.success}</p>}
    {state.loading && <p role="status">Loading authorized security evidence…</p>}
    {state.busy && <p role="status">Loading incident details or saving the reviewed update…</p>}
    {mode === 'incidents' && <p>Date filters apply to incident creation time. Status reflects the current persisted state.</p>}
    {mode === 'dashboard' && state.overview && <OverviewView data={state.overview} />}
    {state.risk && <><h2>Latest visible employee risk</h2><RiskCard risk={state.risk} /></>}
    {mode !== 'dashboard' && state.page && <>
      <p>{state.page.total} visible results · Showing {state.page.total ? state.offset + 1 : 0}–{Math.min(state.offset + state.page.items.length, state.page.total)}</p>
      {!state.page.items.length && <p className="monitor-empty">No matching evidence in the selected authorized scope and period.</p>}
      {mode === 'detections' && <div className="monitor-list">{(state.page.items as Detection[]).map(event => <DetectionCard key={event.id} event={event} />)}</div>}
      {mode === 'incidents' && <div className="monitor-list">{(state.page.items as Incident[]).map(incident => <article className="monitor-card" key={incident.id}>
        <div className="monitor-heading"><h2>{incident.title}</h2><Severity value={incident.severity} /></div>
        <p>{incident.status} · Created {formatTime(incident.created_at)} · Updated {formatTime(incident.updated_at)}</p>
        <p>{incident.description}</p><p>Assigned to: <code>{incident.assigned_to_id || 'Unassigned'}</code></p>
        <button disabled={state.busy || state.loading} onClick={() => void controller.openIncident(incident.id)}>View incident and history</button></article>)}</div>}
      {mode === 'timeline' && <ActivityList items={state.page.items as Activity[]} />}
      <div className="monitor-pagination"><button disabled={state.offset === 0 || state.loading || state.busy} onClick={() => void controller.load(state.filters, Math.max(0, state.offset - 20))}>Previous</button>
        <button disabled={state.offset + 20 >= state.page.total || state.loading || state.busy} onClick={() => void controller.load(state.filters, state.offset + 20)}>Next</button></div>
    </>}
    {state.detail && <IncidentPanel key={state.detail.id + state.detail.updated_at} controller={controller} state={state} />}
  </section>;
}

export function DetectionCard({ event }: { event: Detection }) {
  const session = typeof event.evidence?.session_ref === 'string' ? event.evidence.session_ref : null;
  return <article className="monitor-card"><div className="monitor-heading"><h3>{event.event_type.replaceAll('_', ' ')}</h3><Severity value={event.severity} /></div>
    <p>{formatTime(event.timestamp)} · Employee <code>{event.actor_id || 'Unavailable'}</code> · Resource <code>{event.resource_id || 'Unscoped'}</code></p>
    <p>{event.description}</p>{session && <p>Session fingerprint <code>{session}</code></p>}
    <Evidence value={event.evidence} />
    <div className="monitor-nav">{event.actor_id && <Link to={'/admin/timeline?employee_id=' + encodeURIComponent(event.actor_id)}>Employee activity</Link>}
      {session && <Link to={'/admin/timeline?session_ref=' + encodeURIComponent(session)}>Session activity</Link>}
      {event.related_incidents?.map(i => <Link key={i.id} to={'/admin/incidents?incident_id=' + encodeURIComponent(i.id)}>Incident {i.id} · {i.status}</Link>)}</div>
  </article>;
}

export function ActivityList({ items }: { items: Activity[] }) {
  return <ol className="monitor-timeline">{items.map(item => <li key={item.id}>
    <time dateTime={item.timestamp}>{formatTime(item.timestamp)}</time><article className="monitor-card">
      <div className="monitor-heading"><h3>{item.category.replaceAll('_', ' ')}</h3><Severity value={item.severity || item.outcome} /></div>
      <p>{item.explanation}</p>{item.category === 'ACCESS_ALLOWED' && <p>Authorization allowed the attempt; this alone is not evidence of business-data disclosure.</p>}
      {item.category === 'ACCESS_DENIED' && <p>Denied attempt · zero exposure from this request.</p>}
      {item.category === 'DATA_DISCLOSED' && <p>Application-prepared disclosure · transport UNKNOWN · user receipt is not established.</p>}
      <p>Employee / actor <code>{item.actor_id || 'Unavailable'}</code> · Departments <code>{item.department_ids.join(', ') || 'Unresolved / organization scope'}</code></p>
      {item.resource_id && <p>Resource <code>{item.resource_id}</code>{item.record_id && <> · Record <code>{item.record_id}</code></>} {item.sensitivity}</p>}
      {item.status && <p>Recorded incident status: {item.status}</p>}
      {item.session_ref && <p>Session fingerprint <code>{item.session_ref}</code></p>}
      <p>Evidence reference <code>{item.id}</code></p>
      {item.details && <Evidence value={item.details} />}
      {item.incident_id && <Link to={'/admin/incidents?incident_id=' + encodeURIComponent(item.incident_id)}>Review incident</Link>}
      {item.related_incidents.map(i => <Link key={i.id} to={'/admin/incidents?incident_id=' + encodeURIComponent(i.id)}>Incident {i.id} · {i.status}</Link>)}
    </article></li>)}</ol>;
}

export function OverviewView({ data }: { data: Overview }) {
  const metrics = [['Detections', data.detections], ['High severity', data.high_detections], ['Critical severity', data.critical_detections],
    ['Employees with elevated latest visible risk', data.elevated_employees], ['Open incidents', data.open_incidents], ['Under investigation', data.investigating_incidents],
    ['Resolved incidents', data.resolved_incidents], ['Closed incidents', data.closed_incidents], ['Prepared record disclosures', data.disclosure_events], ['Distinct disclosed records', data.distinct_records]];
  return <><p>Evidence period: {formatTime(data.start)} – {formatTime(data.end)}. Incident counts show current visible status across all dates.</p>
    <div className="monitor-metrics">{metrics.map(([label, value]) => <article className="monitor-card" key={label}><span>{label}</span><strong>{value}</strong></article>)}</div>
    <p>Disclosure counts describe application-prepared responses; network delivery and user receipt remain unknown.</p>
    <h2>Latest visible employee risk</h2>{!data.employee_risks.length && <p>No recorded employee assessments in this period.</p>}
    <div className="monitor-list">{data.employee_risks.map(risk => <RiskCard key={risk.id} risk={risk} />)}</div>
    <h2>Recent detections</h2>{!data.recent_detections.length && <p>No visible detections in this period.</p>}
    <div className="monitor-list">{data.recent_detections.map(event => <DetectionCard key={event.id} event={event} />)}</div>
    <h2>Recent security activity</h2>{!data.recent_activity.length && <p>No matching security activity.</p>}<ActivityList items={data.recent_activity} />
  </>;
}

function IncidentPanel({ controller, state }: { controller: MonitoringController; state: MonitoringState }) {
  const incident = state.detail!;
  const [notes, setNotes] = useState(incident.resolution_notes || '');
  const [status, setStatus] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  return <section className="monitor-detail" aria-label="Incident details"><button disabled={state.busy} onClick={() => controller.closeIncident()}>Close details</button>
    <h2>{incident.title}</h2><p>{incident.description}</p><p><Severity value={incident.severity} /> {incident.status}</p>
    <p>Created {formatTime(incident.created_at)} · Updated {formatTime(incident.updated_at)}</p>
    <p>Reporter <code>{incident.reporter_id || 'Unavailable'}</code> · Assignee <code>{incident.assigned_to_id || 'Unassigned'}</code> · Resource <code>{incident.resource_id || 'Organization scope'}</code></p>
    <form className="monitor-incident-form" onSubmit={e => { e.preventDefault(); void controller.updateIncident(status, notes, confirmed); }}>
      <label>Status action<select value={status} onChange={e => { setStatus(e.target.value); setConfirmed(false); }}><option value="">Keep current status / save notes</option>{nextStatus[incident.status] && <option value={nextStatus[incident.status]}>{nextStatus[incident.status]}</option>}</select></label>
      <label>Resolution notes<textarea value={notes} onChange={e => { setNotes(e.target.value); setConfirmed(false); }} /></label>
      <label className="monitor-confirm"><input type="checkbox" checked={confirmed} onChange={e => setConfirmed(e.target.checked)} />I reviewed this incident and confirm the update.</label>
      <button type="submit" disabled={state.busy || !confirmed}>Save reviewed incident update</button>
    </form>
    <h3>Recorded incident history</h3><p>Only persisted actions are shown; earlier notes cannot be reconstructed from missing historical snapshots.</p>
    <ul>{incident.history.map(h => <li key={h.id}>{formatTime(h.timestamp)} · {h.action} · {h.status || 'No recorded status'} · actor {h.actor_id}</li>)}</ul>
    <h3>Linked detections</h3>{!incident.detection_evidence.length && <p>No linked detection evidence.</p>}{incident.detection_evidence.map(event => <DetectionCard key={event.id} event={event} />)}
  </section>;
}
