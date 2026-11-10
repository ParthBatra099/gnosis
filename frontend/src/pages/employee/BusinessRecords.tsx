import { useEffect, useState, useSyncExternalStore } from 'react';
import { Database, RefreshCw } from 'lucide-react';
import { useAuth } from '../../hooks/useAuth';
import { BusinessRecordsController, connectBusinessRecords } from './businessRecordsController';
import type { BusinessRecordsState } from './businessRecordsController';
import './BusinessRecords.css';

export function BusinessRecords() {
  const { user } = useAuth();
  return <ConnectedBusinessRecords key={user?.id + ':' + user?.organization_role} />;
}
function ConnectedBusinessRecords() {
  const [controller] = useState(() => new BusinessRecordsController());
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot);
  useEffect(() => connectBusinessRecords(controller), [controller]);
  return <BusinessRecordsView controller={controller} state={state} />;
}

export function BusinessRecordsView({ controller, state }: { controller: BusinessRecordsController; state: BusinessRecordsState }) {
  const selected = state.resources.find(resource => resource.id === state.selectedId);
  const response = state.response;
  return <section className="business-records" aria-busy={state.busy || state.loadingMetadata}>
    <header className="business-records-heading"><div><p className="business-records-kicker">EMPLOYEE WORKSPACE</p>
      <h1><Database aria-hidden="true" /> Business records</h1><p>Browse resource metadata, then explicitly request a page of records. The backend decides access for every request.</p></div>
      <button type="button" disabled={state.loadingMetadata || state.busy || state.outcome === 'session-ended'} onClick={() => void controller.loadMetadata()}><RefreshCw size={15} aria-hidden="true" /> Refresh resource list</button>
    </header>
    <div className="business-records-notice">A listed resource is not proof of permission. Selecting it does not request records. Every record request, including pagination or repeating a page, may create new server-side disclosure evidence.</div>
    {state.loadingMetadata && <p role="status">Loading resource metadata only…</p>}
    {!state.loadingMetadata && !state.resources.length && state.outcome !== 'session-ended' && <p>No resource metadata is available. No business records have been requested by loading this page.</p>}
    {state.error && <div className="business-records-error" role="alert">{state.error}</div>}
    <form className="business-records-controls" onSubmit={event => { event.preventDefault(); void controller.request(); }}>
      <label htmlFor="business-resource">Resource<select id="business-resource" value={state.selectedId}
        disabled={state.loadingMetadata || state.outcome === 'session-ended'} onChange={event => controller.select(event.target.value)}>
        <option value="">Select a resource</option>{state.resources.map(resource => <option key={resource.id} value={resource.id}>{resource.name} · {resource.sensitivity || 'Classification unavailable'}</option>)}
      </select></label>
      <label htmlFor="business-page-size">Records per page<select id="business-page-size" value={state.limit}
        disabled={state.loadingMetadata || state.outcome === 'session-ended'} onChange={event => controller.setLimit(Number(event.target.value))}>
        {[10, 25, 50, 100].map(limit => <option key={limit} value={limit}>{limit}</option>)}</select></label>
      <button type="submit" disabled={!selected || state.busy || state.loadingMetadata || state.outcome === 'session-ended'}>{state.busy ? 'Requesting records…' : 'Request records'}</button>
    </form>
    {selected && <section className="business-records-resource" aria-label="Selected resource metadata"><h2>{selected.name}</h2>
      <p>{selected.description || 'No description provided.'}</p><dl><dt>Classification</dt><dd>{selected.sensitivity || 'Unavailable'}</dd>
        <dt>Department ID</dt><dd>{selected.department_id || 'Unavailable'}</dd><dt>Resource ID</dt><dd>{selected.id}</dd></dl>
      {!response && !state.busy && state.outcome === 'idle' && <p>No records requested for this selection.</p>}</section>}
    {state.busy && <p role="status">Waiting for backend authorization and record processing…</p>}
    {response && <section className="business-records-results" aria-label="Returned business records">
      <div className="business-records-result-heading"><h2>Access allowed — records response received</h2><span>{response.records.length} returned</span></div>
      <dl className="business-records-evidence"><dt>Response ID</dt><dd>{response.response_id}</dd><dt>Backend disclosure semantics</dt><dd>{response.disclosure_semantics}</dd></dl>
      <p className="business-records-semantics">APPLICATION_COMPLETE means application-side processing completed. The disclosure ledger does not prove network delivery or that a person received or viewed the data. An empty page contains no record disclosures.</p>
      <p>Offset {state.offset} · Page size {state.limit} · {response.records.length ? `Positions ${state.offset + 1}–${state.offset + response.records.length}` : 'No records returned for this page'}</p>
      <div className="business-records-list">{response.records.map(record => <article className="business-records-card" key={record.id}>
        <header><h3>{record.category}</h3><span>{record.sensitivity}</span></header><p>Record ID: <code>{record.id}</code></p>
        <pre aria-label={'Values for record ' + record.id}>{JSON.stringify(record.values, null, 2)}</pre>
      </article>)}</div>
      <nav className="business-records-pagination" aria-label="Business record pagination">
        <button type="button" disabled={state.busy || state.offset === 0} onClick={() => void controller.request(Math.max(0, state.offset - state.limit))}>Previous page</button>
        <button type="button" disabled={state.busy || response.records.length < state.limit} onClick={() => void controller.request(state.offset + state.limit)}>Request next page</button>
      </nav><p>The API supplies no total count. A full page means another page may exist; the next page may be empty.</p>
    </section>}
    <p className="business-records-footer">Changing selection clears this view but does not undo a request already submitted to the backend. No record request is automatically retried.</p>
  </section>;
}
