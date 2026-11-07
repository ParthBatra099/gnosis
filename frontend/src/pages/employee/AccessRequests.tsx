import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';

import {
    createAccessRequest,
    getMyAccessRequests,
} from '../../api/accessRequests';

import {
    getResourceMetadata,
} from '../../api/resources';

import type { ResourceMetadata } from '../../api/resources';
import type { AccessRequest } from '../../api/accessRequests';

import './AccessRequests.css';

type Permission = 'read' | 'write' | 'delete';

export function AccessRequests() {
    const [resources, setResources] = useState<ResourceMetadata[]>([]);
    const [requests, setRequests] = useState<AccessRequest[]>([]);

    const [resourceId, setResourceId] = useState('');
    const [permission, setPermission] =
        useState<Permission>('read');
    const [reason, setReason] = useState('');

    const [loading, setLoading] = useState(true);
    const [submitting, setSubmitting] = useState(false);

    const [error, setError] = useState<string | null>(null);
    const [success, setSuccess] = useState<string | null>(null);

    useEffect(() => {
        async function loadData() {
            try {
                setLoading(true);
                setError(null);

                const [resourceData, requestData] =
                    await Promise.all([
                        getResourceMetadata(),
                        getMyAccessRequests(),
                    ]);

                setResources(resourceData);
                setRequests(requestData);
            } catch {
                setError(
                    'Unable to load resources and access requests.'
                );
            } finally {
                setLoading(false);
            }
        }

        void loadData();
    }, []);

    async function handleSubmit(
        event: FormEvent<HTMLFormElement>
    ) {
        event.preventDefault();

        if (!resourceId) {
            setError('Please select a resource.');
            setSuccess(null);
            return;
        }

        try {
            setSubmitting(true);
            setError(null);
            setSuccess(null);

            const createdRequest = await createAccessRequest({
                resource_id: resourceId,
                permission,
                reason: reason.trim(),
            });

            setRequests((previous) => [
                createdRequest,
                ...previous,
            ]);

            setResourceId('');
            setPermission('read');
            setReason('');

            setSuccess(
                'Your access request has been submitted successfully.'
            );
        } catch (requestError: any) {
            const detail =
                requestError?.response?.data?.detail;

            if (typeof detail === 'string') {
                setError(detail);
            } else {
                setError(
                    'Unable to submit your access request. Please try again.'
                );
            }
        } finally {
            setSubmitting(false);
        }
    }

    function getResourceName(resourceId: string) {
        const resource = resources.find(
            (item) => item.id === resourceId
        );

        return resource?.name || 'Unknown resource';
    }

    function formatDate(dateString: string) {
        if (!dateString) {
            return '—';
        }

        const date = new Date(dateString);

        if (Number.isNaN(date.getTime())) {
            return dateString;
        }

        return date.toLocaleDateString(undefined, {
            day: 'numeric',
            month: 'short',
            year: 'numeric',
        });
    }

    function getStatusClass(status: string) {
        return `access-request-status access-request-status-${status.toLowerCase()}`;
    }

    if (loading) {
        return (
            <div className="access-requests-page">
                <div className="access-requests-loading">
                    Loading access requests...
                </div>
            </div>
        );
    }

    return (
        <div className="access-requests-page">

            {/* =====================================================
          PAGE HEADER
      ===================================================== */}

            <section className="access-requests-header">
                <div>
                    <span className="access-requests-eyebrow">
                        ACCESS MANAGEMENT
                    </span>

                    <h1>
                        Access Requests
                    </h1>

                    <p>
                        Request access to organizational resources
                        and track the status of your requests.
                    </p>
                </div>
            </section>


            {/* =====================================================
          MESSAGES
      ===================================================== */}

            {error && (
                <div className="access-request-message access-request-error">
                    {error}
                </div>
            )}

            {success && (
                <div className="access-request-message access-request-success">
                    {success}
                </div>
            )}


            {/* =====================================================
          REQUEST FORM
      ===================================================== */}

            <section className="access-request-card">

                <div className="access-request-card-header">
                    <div>
                        <span className="access-request-card-eyebrow">
                            NEW REQUEST
                        </span>

                        <h2>
                            Request resource access
                        </h2>

                        <p>
                            Select a resource and permission level.
                            Your request will be reviewed according to
                            GNOSIS security policy.
                        </p>
                    </div>
                </div>


                <form
                    className="access-request-form"
                    onSubmit={handleSubmit}
                >

                    {/* Resource */}

                    <div className="access-request-field">

                        <label htmlFor="resource">
                            Resource
                        </label>

                        <select
                            id="resource"
                            value={resourceId}
                            onChange={(event) =>
                                setResourceId(event.target.value)
                            }
                            disabled={submitting}
                        >
                            <option value="">
                                Select a resource
                            </option>

                            {resources.map((resource) => (
                                <option
                                    key={resource.id}
                                    value={resource.id}
                                >
                                    {resource.name}
                                </option>
                            ))}
                        </select>

                    </div>


                    {/* Permission */}

                    <div className="access-request-field">

                        <label htmlFor="permission">
                            Permission
                        </label>

                        <select
                            id="permission"
                            value={permission}
                            onChange={(event) =>
                                setPermission(
                                    event.target.value as Permission
                                )
                            }
                            disabled={submitting}
                        >
                            <option value="read">
                                Read
                            </option>

                            <option value="write">
                                Write
                            </option>

                            <option value="delete">
                                Delete
                            </option>
                        </select>

                    </div>


                    {/* Reason */}

                    <div className="access-request-field">

                        <label htmlFor="reason">
                            Reason
                            <span className="access-request-optional">
                                Optional
                            </span>
                        </label>

                        <textarea
                            id="reason"
                            value={reason}
                            onChange={(event) =>
                                setReason(event.target.value)
                            }
                            placeholder="Explain why you need access to this resource..."
                            rows={5}
                            disabled={submitting}
                        />

                    </div>


                    {/* Submit */}

                    <div className="access-request-form-footer">

                        <p>
                            Access is granted only according to
                            your organization's security policy.
                        </p>

                        <button
                            type="submit"
                            disabled={submitting || !resourceId}
                            className="access-request-submit"
                        >
                            {submitting
                                ? 'Submitting...'
                                : 'Submit request'}
                        </button>

                    </div>

                </form>

            </section>


            {/* =====================================================
          MY REQUESTS
      ===================================================== */}

            <section className="my-access-requests">

                <div className="my-access-requests-header">

                    <div>
                        <span className="access-request-card-eyebrow">
                            REQUEST HISTORY
                        </span>

                        <h2>
                            Your access requests
                        </h2>
                    </div>

                    <span className="access-request-count">
                        {requests.length}
                    </span>

                </div>


                {requests.length === 0 ? (

                    <div className="access-requests-empty">

                        <h3>
                            No access requests yet
                        </h3>

                        <p>
                            When you request access to a resource,
                            your requests will appear here.
                        </p>

                    </div>

                ) : (

                    <div className="access-request-list">

                        {requests.map((request) => (

                            <article
                                key={request.id}
                                className="access-request-item"
                            >

                                <div className="access-request-item-main">

                                    <h3>
                                        {getResourceName(
                                            request.resource_id
                                        )}
                                    </h3>

                                    <div className="access-request-meta">

                                        <span>
                                            {request.permission.toUpperCase()}
                                        </span>

                                        <span>
                                            Requested{' '}
                                            {formatDate(
                                                request.created_at
                                            )}
                                        </span>

                                    </div>

                                    {request.reason && (
                                        <p className="access-request-reason">
                                            {request.reason}
                                        </p>
                                    )}

                                </div>


                                <div className="access-request-item-status">

                                    <span
                                        className={getStatusClass(
                                            request.status
                                        )}
                                    >
                                        {request.status}
                                    </span>

                                </div>

                            </article>

                        ))}

                    </div>

                )}

            </section>

        </div>
    );
}