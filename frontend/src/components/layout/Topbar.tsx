import {
  Menu,
  LogOut,
  ShieldCheck,
} from 'lucide-react';

import { useAuth } from '../../hooks/useAuth';

interface TopbarProps {
  pageTitle: string;
  onToggleMobile: () => void;
}

export function Topbar({
  pageTitle,
  onToggleMobile,
}: TopbarProps) {
  const { user, logout } = useAuth();

  return (
    <header className="gnosis-topbar">

      {/* =========================================
          LEFT
      ========================================== */}

      <div className="gnosis-topbar-left">

        <button
          type="button"
          className="gnosis-mobile-toggle"
          onClick={onToggleMobile}
          aria-label="Toggle navigation menu"
        >
          <Menu />
        </button>

        <div className="gnosis-topbar-heading">

          <span className="gnosis-topbar-kicker">
            GNOSIS
          </span>

          <h1 className="gnosis-topbar-page-title">
            {pageTitle}
          </h1>

        </div>

      </div>


      {/* =========================================
          RIGHT
      ========================================== */}

      <div className="gnosis-topbar-right">

        <div className="gnosis-topbar-security">

          <span className="gnosis-topbar-security-icon">
            <ShieldCheck />
          </span>

          <div>
            <span className="gnosis-topbar-security-title">
              Secure session
            </span>

            <span className="gnosis-topbar-security-status">
              <span />
              Protected
            </span>
          </div>

        </div>


        {user && (
          <div className="gnosis-topbar-user">

            <div className="gnosis-topbar-avatar">
              {(user.name || 'U')
                .charAt(0)
                .toUpperCase()}
            </div>

            <div className="gnosis-topbar-user-details">

              <span className="gnosis-topbar-user-name">
                {user.name}
              </span>

              <span className="gnosis-topbar-user-role">
                {user.role}
              </span>

            </div>

          </div>
        )}


        <button
          type="button"
          className="gnosis-topbar-action-btn"
          onClick={logout}
          title="Sign out"
          aria-label="Sign out"
        >
          <LogOut />
        </button>

      </div>

    </header>
  );
}