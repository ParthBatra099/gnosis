import React from 'react';
import { Link } from 'react-router-dom';
import {
  ArrowRight,
  Database,
  KeyRound,
  MessageSquare,
  ShieldCheck,
} from 'lucide-react';

export const EmployeeDashboard: React.FC = () => {
  return (
    <div className="employee-dashboard employee-dashboard-secondary">

      {/* =====================================================
          PAGE HEADER
      ===================================================== */}

      <section className="employee-page-header">

        <div>

          <span className="employee-panel-kicker">
            EMPLOYEE WORKSPACE
          </span>

          <h1>
            Your workspace
          </h1>

          <p>
            Manage your resources, access requests, and
            security interactions with GNOSIS.
          </p>

        </div>

        <div className="employee-page-status">
          <span />
          Protected
        </div>

      </section>


      {/* =====================================================
          ACCESS OVERVIEW
      ===================================================== */}

      <section className="employee-overview-grid">

        <div className="employee-stat-card">

          <div className="employee-stat-icon blue">
            <Database />
          </div>

          <div className="employee-stat-content">

            <span className="employee-stat-label">
              RESOURCE ACCESS
            </span>

            <strong>
              Authorized resources
            </strong>

            <p>
              View the organizational resources
              available to you.
            </p>

          </div>

        </div>


        <div className="employee-stat-card">

          <div className="employee-stat-icon purple">
            <KeyRound />
          </div>

          <div className="employee-stat-content">

            <span className="employee-stat-label">
              ACCESS CONTROL
            </span>

            <strong>
              Access requests
            </strong>

            <p>
              Review or submit requests for protected
              resources.
            </p>

          </div>

        </div>


        <div className="employee-stat-card">

          <div className="employee-stat-icon green">
            <ShieldCheck />
          </div>

          <div className="employee-stat-content">

            <span className="employee-stat-label">
              SECURITY
            </span>

            <strong>
              Session protected
            </strong>

            <p>
              Your current GNOSIS session is authenticated.
            </p>

          </div>

        </div>

      </section>


      {/* =====================================================
          ACTIONS
      ===================================================== */}

      <section className="employee-main-grid">

        <div className="employee-panel">

          <div className="employee-panel-heading">

            <div>

              <span className="employee-panel-kicker">
                GNOSIS ASSISTANT
              </span>

              <h2>
                Ask GNOSIS
              </h2>

            </div>

            <MessageSquare className="employee-panel-heading-icon" />

          </div>

          <p className="employee-dashboard-description">
            Ask questions about resources, access,
            permissions, or information available to your
            account.
          </p>

          <Link
            to="/ask-gnosis"
            className="employee-dashboard-button"
          >
            Open GNOSIS
            <ArrowRight />
          </Link>

        </div>


        <div className="employee-panel">

          <div className="employee-panel-heading">

            <div>

              <span className="employee-panel-kicker">
                RESOURCE ACCESS
              </span>

              <h2>
                Explore resources
              </h2>

            </div>

            <Database className="employee-panel-heading-icon" />

          </div>

          <p className="employee-dashboard-description">
            Browse resources and view the information
            your current permissions allow you to access.
          </p>

          <Link
            to="/employee/resources"
            className="employee-dashboard-button"
          >
            View resources
            <ArrowRight />
          </Link>

        </div>

      </section>


      {/* =====================================================
          ACCESS REQUEST
      ===================================================== */}

      <section className="employee-request-banner">

        <div className="employee-request-icon">
          <KeyRound />
        </div>

        <div className="employee-request-content">

          <span>
            NEED ADDITIONAL ACCESS?
          </span>

          <strong>
            Request access to a protected resource.
          </strong>

          <p>
            Submit an access request through GNOSIS and
            track its status from your workspace.
          </p>

        </div>

        <Link
          to="/employee/access-requests"
          className="employee-request-button"
        >
          Request access
          <ArrowRight />
        </Link>

      </section>

    </div>
  );
};