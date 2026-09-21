import { Link } from 'react-router-dom';
import {
  ArrowRight,
  Database,
  KeyRound,
  MessageSquare,
  ShieldCheck,
  User,
  Mail,
  LockKeyhole,
  Sparkles,
} from 'lucide-react';

import { useAuth } from '../../hooks/useAuth';
import './EmployeeHome.css';


export function EmployeeHome() {
  const { user } = useAuth();

  const getGreeting = () => {
    const hour = new Date().getHours();

    if (hour < 12) {
      return 'Good morning';
    }

    if (hour < 18) {
      return 'Good afternoon';
    }

    return 'Good evening';
  };

  const firstName =
    user?.name?.split(' ')[0] || 'there';

  return (
    <div className="employee-dashboard">

      {/* =====================================================
          WELCOME HEADER
      ===================================================== */}

      <section className="employee-hero">

        <div className="employee-hero-content">

          <div className="employee-hero-eyebrow">
            <span className="employee-hero-dot" />
            GNOSIS WORKSPACE
          </div>

          <h1>
            {getGreeting()}, {firstName}
            <span className="employee-wave">👋</span>
          </h1>

          <p>
            Everything you need to securely access your
            organization's resources in one place.
          </p>

        </div>

        <div className="employee-hero-actions">

          <Link
            to="/ask-gnosis"
            className="employee-primary-action"
          >
            <MessageSquare />
            Ask GNOSIS
            <ArrowRight />
          </Link>

          <Link
            to="/employee/access-requests"
            className="employee-secondary-action"
          >
            <KeyRound />
            Request access
          </Link>

        </div>

      </section>


      {/* =====================================================
          OVERVIEW CARDS
      ===================================================== */}

      <section className="employee-overview-grid">

        <div className="employee-stat-card">

          <div className="employee-stat-icon blue">
            <Database />
          </div>

          <div className="employee-stat-content">

            <span className="employee-stat-label">
              RESOURCES
            </span>

            <strong>
              Authorized
            </strong>

            <p>
              View the resources available to your account.
            </p>

          </div>

          <Link
            to="/employee/resources"
            className="employee-card-arrow"
          >
            <ArrowRight />
          </Link>

        </div>


        <div className="employee-stat-card">

          <div className="employee-stat-icon purple">
            <KeyRound />
          </div>

          <div className="employee-stat-content">

            <span className="employee-stat-label">
              ACCESS
            </span>

            <strong>
              Requests
            </strong>

            <p>
              Review and manage your access requests.
            </p>

          </div>

          <Link
            to="/employee/access-requests"
            className="employee-card-arrow"
          >
            <ArrowRight />
          </Link>

        </div>


        <div className="employee-stat-card employee-security-card">

          <div className="employee-stat-icon green">
            <ShieldCheck />
          </div>

          <div className="employee-stat-content">

            <span className="employee-stat-label">
              SECURITY
            </span>

            <strong>
              Protected
            </strong>

            <p>
              Your GNOSIS session is authenticated and active.
            </p>

          </div>

          <span className="employee-protected-badge">
            <span />
            Secure
          </span>

        </div>

      </section>


      {/* =====================================================
          MAIN GRID
      ===================================================== */}

      <section className="employee-main-grid">

        {/* =================================================
            QUICK ACTIONS
        ================================================= */}

        <div className="employee-panel employee-actions-panel">

          <div className="employee-panel-heading">

            <div>
              <span className="employee-panel-kicker">
                GET STARTED
              </span>

              <h2>
                Quick actions
              </h2>
            </div>

            <Sparkles className="employee-panel-heading-icon" />

          </div>


          <div className="employee-action-list">

            <Link
              to="/ask-gnosis"
              className="employee-large-action"
            >

              <div className="employee-large-action-icon blue">
                <MessageSquare />
              </div>

              <div className="employee-large-action-content">

                <strong>
                  Ask GNOSIS
                </strong>

                <span>
                  Ask questions about information available
                  to your account.
                </span>

              </div>

              <ArrowRight className="employee-large-action-arrow" />

            </Link>


            <Link
              to="/employee/access-requests"
              className="employee-large-action"
            >

              <div className="employee-large-action-icon purple">
                <KeyRound />
              </div>

              <div className="employee-large-action-content">

                <strong>
                  Request resource access
                </strong>

                <span>
                  Submit and review requests for protected
                  organizational resources.
                </span>

              </div>

              <ArrowRight className="employee-large-action-arrow" />

            </Link>


            <Link
              to="/employee/resources"
              className="employee-large-action"
            >

              <div className="employee-large-action-icon green">
                <Database />
              </div>

              <div className="employee-large-action-content">

                <strong>
                  Explore resources
                </strong>

                <span>
                  Browse the resources your account is
                  authorized to access.
                </span>

              </div>

              <ArrowRight className="employee-large-action-arrow" />

            </Link>

          </div>

        </div>


        {/* =================================================
            ACCOUNT
        ================================================= */}

        {user && (
          <div className="employee-panel employee-account-panel">

            <div className="employee-panel-heading">

              <div>
                <span className="employee-panel-kicker">
                  YOUR ACCOUNT
                </span>

                <h2>
                  Identity
                </h2>
              </div>

              <div className="employee-identity-status">
                <span />
                Active
              </div>

            </div>


            <div className="employee-profile">

              <div className="employee-profile-avatar">
                {(user.name || 'U')
                  .charAt(0)
                  .toUpperCase()}
              </div>

              <div className="employee-profile-main">

                <strong>
                  {user.name}
                </strong>

                <span>
                  {user.role}
                </span>

              </div>

            </div>


            <div className="employee-account-details">

              <div className="employee-account-detail">

                <div className="employee-detail-icon">
                  <Mail />
                </div>

                <div>
                  <span>Email address</span>
                  <strong>{user.email}</strong>
                </div>

              </div>


              <div className="employee-account-detail">

                <div className="employee-detail-icon">
                  <LockKeyhole />
                </div>

                <div>
                  <span>Access level</span>
                  <strong>{user.role}</strong>
                </div>

              </div>


              <div className="employee-account-detail">

                <div className="employee-detail-icon">
                  <User />
                </div>

                <div>
                  <span>Account status</span>
                  <strong>Authenticated</strong>
                </div>

              </div>

            </div>

          </div>
        )}

      </section>


      {/* =====================================================
          SECURITY FOOTER
      ===================================================== */}

      <section className="employee-security-footer">

        <div className="employee-security-footer-icon">
          <ShieldCheck />
        </div>

        <div>

          <strong>
            GNOSIS Security Engine
          </strong>

          <span>
            Your session is protected by GNOSIS access controls.
          </span>

        </div>

        <div className="employee-security-footer-status">
          <span />
          Protected
        </div>

      </section>

    </div>
  );
}