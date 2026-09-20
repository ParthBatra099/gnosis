import { Menu, LogOut } from 'lucide-react';
import { useAuth } from '../../hooks/useAuth';

interface TopbarProps {
  pageTitle: string;
  onToggleMobile: () => void;
}

export function Topbar({ pageTitle, onToggleMobile }: TopbarProps) {
  const { user, logout } = useAuth();

  return (
    <header className="gnosis-topbar">
      <div className="gnosis-topbar-left">
        <button
          type="button"
          className="gnosis-mobile-toggle"
          onClick={onToggleMobile}
          aria-label="Toggle navigation menu"
        >
          <Menu style={{ width: '1.25rem', height: '1.25rem' }} />
        </button>

        <h2 className="gnosis-topbar-page-title">{pageTitle}</h2>

        <div className="gnosis-topbar-status-badge">
          <span className="gnosis-status-dot" />
          <span>SYSTEM ONLINE</span>
        </div>
      </div>

      <div className="gnosis-topbar-right">
        {user && (
          <div className="gnosis-topbar-user-info">
            <div className="gnosis-topbar-user-details">
              <span className="gnosis-topbar-user-name">{user.name}</span>
              <span className="gnosis-topbar-user-role">{user.role}</span>
            </div>
          </div>
        )}

        <button
          type="button"
          className="gnosis-topbar-action-btn"
          onClick={logout}
          title="Sign Out"
          aria-label="Sign Out"
        >
          <LogOut style={{ width: '1rem', height: '1rem' }} />
        </button>
      </div>
    </header>
  );
}