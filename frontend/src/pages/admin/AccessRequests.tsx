import { useEffect, useState } from 'react';
import {
    CheckCircle,
    XCircle,
    Clock,
    ShieldCheck,
    RefreshCw,
} from 'lucide-react';

import {
    getPendingAccessRequests,
    approveAccessRequest,
    rejectAccessRequest,
} from "../../api/accessRequests";

import './AccessRequests.css';

interface AccessRequest {
    id: string;
    requester_id: string;
    resource_id: string;
    permission: string;
    reason?: string | null;
    status: string;
    created_at: string;
}

export function AccessRequests() {
    const [requests, setRequests] = useState<AccessRequest[]>([]);
    const [loading, setLoading] = useState(true);
    const [processingId, setProcessingId] = useState<string | null>(null);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');

    async function loadRequests() {
        try {
            setLoading(true);
            setError('');

            const data = await getPendingAccessRequests();
            setRequests(data);
        } catch (err) {
            console.error(err);
            setError('Unable to load pending access requests.');
        } finally {
            setLoading(false);
        }
    }

    useEffect(() => {
        let active = true;

        getPendingAccessRequests()
            .then((data) => {
                if (active) setRequests(data);
            })
            .catch((err: unknown) => {
                if (active) {
                    console.error(err);
                    setError('Unable to load pending access requests.');
                }
            })
            .finally(() => {
                if (active) setLoading(false);
            });

        return () => { active = false; };
    }, []);

    async function handleApprove(requestId: string) {
        try {
            setProcessingId(requestId);
            setError('');
            setSuccess('');

            await approveAccessRequest(requestId);

            setSuccess('Access request approved successfully.');

            await loadRequests();
        } catch (err) {
            console.error(err);
            setError('Unable to approve this access request.');
        } finally {
            setProcessingId(null);
        }
    }

    async function handleReject(requestId: string) {
        try {
            setProcessingId(requestId);
            setError('');
            setSuccess('');

            await rejectAccessRequest(requestId);

            setSuccess('Access request rejected.');

            await loadRequests();
        } catch (err) {
            console.error(err);
            setError('Unable to reject this access request.');
        } finally {
            setProcessingId(null);
        }
    }

    return (
        <div className="admin-access-requests">

            <header className="admin-access-header">
                <div>
                    <span className="admin-access-kicker">
                        ACCESS MANAGEMENT
                    </span>

                    <h1>Access Requests</h1>

                    <p>
                        Review and manage pending requests for organizational resources.
                    </p>
                </div>

                <button
                    type="button"
                    className="admin-refresh-button"
                    onClick={loadRequests}
                    disabled={loading}
                >
                    <RefreshCw size={17} />
                    Refresh
                </button>
            </header>

            {success && (
                <div className="admin-access-alert admin-access-alert--success">
                    <CheckCircle size={18} />
                    {success}
                </div>
            )}

            {error && (
                <div className="admin-access-alert admin-access-alert--error">
                    <XCircle size={18} />
                    {error}
                </div>
            )}

            <section className="admin-access-summary">
                <div className="admin-access-summary-icon">
                    <Clock size={21} />
                </div>

                <div>
                    <span>Pending requests</span>
                    <strong>{requests.length}</strong>
                </div>
            </section>

            <section className="admin-request-panel">

                <div className="admin-request-panel-header">
                    <div>
                        <span className="admin-access-kicker">
                            REVIEW QUEUE
                        </span>

                        <h2>Requests requiring approval</h2>
                    </div>

                    <ShieldCheck size={24} />
                </div>

                {loading ? (
                    <div className="admin-access-empty">
                        Loading access requests...
                    </div>
                ) : requests.length === 0 ? (
                    <div className="admin-access-empty">
                        <CheckCircle size={32} />

                        <strong>No pending requests</strong>

                        <p>
                            There are currently no access requests waiting for review.
                        </p>
                    </div>
                ) : (
                    <div className="admin-request-list">

                        {requests.map((request) => {
                            const processing =
                                processingId === request.id;

                            return (
                                <article
                                    key={request.id}
                                    className="admin-request-card"
                                >

                                    <div className="admin-request-card-main">

                                        <div className="admin-request-icon">
                                            <ShieldCheck size={21} />
                                        </div>

                                        <div className="admin-request-content">

                                            <div className="admin-request-title-row">
                                                <h3>
                                                    Resource request
                                                </h3>

                                                <span className="admin-request-status">
                                                    PENDING
                                                </span>
                                            </div>

                                            <div className="admin-request-details">

                                                <div>
                                                    <span>Resource ID</span>
                                                    <strong>
                                                        {request.resource_id}
                                                    </strong>
                                                </div>

                                                <div>
                                                    <span>Requester ID</span>
                                                    <strong>
                                                        {request.requester_id}
                                                    </strong>
                                                </div>

                                                <div>
                                                    <span>Permission</span>
                                                    <strong>
                                                        {request.permission.toUpperCase()}
                                                    </strong>
                                                </div>

                                                <div>
                                                    <span>Requested</span>
                                                    <strong>
                                                        {new Date(
                                                            request.created_at
                                                        ).toLocaleString()}
                                                    </strong>
                                                </div>

                                            </div>

                                            {request.reason && (
                                                <div className="admin-request-reason">
                                                    <span>Reason</span>
                                                    <p>{request.reason}</p>
                                                </div>
                                            )}

                                        </div>

                                    </div>

                                    <div className="admin-request-actions">

                                        <button
                                            type="button"
                                            className="admin-request-button admin-request-button--reject"
                                            disabled={processing}
                                            onClick={() =>
                                                handleReject(request.id)
                                            }
                                        >
                                            <XCircle size={17} />
                                            Reject
                                        </button>

                                        <button
                                            type="button"
                                            className="admin-request-button admin-request-button--approve"
                                            disabled={processing}
                                            onClick={() =>
                                                handleApprove(request.id)
                                            }
                                        >
                                            <CheckCircle size={17} />
                                            {processing
                                                ? 'Processing...'
                                                : 'Approve'}
                                        </button>

                                    </div>

                                </article>
                            );
                        })}

                    </div>
                )}

            </section>

        </div>
    );
}
