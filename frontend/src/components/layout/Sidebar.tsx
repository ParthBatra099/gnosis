import type { ElementType } from 'react';
import { NavLink } from 'react-router-dom';
import {
  ShieldAlert,
  LayoutDashboard,
  Users,
  Database,
  KeyRound,
  AlertTriangle,
  Activity,
  MessageSquare,
  LogOut,
  User as UserIcon,
} from 'lucide-react';
import { useAuth } from '../../hooks/useAuth';

interface SidebarProps {
  mobileOpen: boolean;
  onCloseMobile: () => void;
}

interface NavItem {
  label: string;
  to: string;
  icon: ElementType;
  enabled: boolean;
}

export function Sidebar({ mobileOpen, onCloseMobile }: SidebarProps) {
  const { user, logout } = useAuth();
  const isAdmin = user?.role?.toUpperCase() === 'ADMIN';

  const employeeNavItems: NavItem[] = [
    { label: 'Dashboard', to: '/employee', icon: LayoutDashboard, enabled: true },
    { label: 'Ask GNOSIS', to: '/ask-gnosis', icon: MessageSquare, enabled: true },
    { label: 'Resources', to: '/employee/resources', icon: Database, enabled: false },
    { label: 'Access Requests', to: '/employee/access-requests', icon: KeyRound, enabled: false },
    { label: 'Activity', to: '/employee/activity', icon: Activity, enabled: false },
  ];

  const adminNavItems: NavItem[] = [
    { label: 'Dashboard', to: '/admin', icon: LayoutDashboard, enabled: true },
    { label: 'Ask GNOSIS', to: '/ask-gnosis', icon: MessageSquare, enabled: true },
    { label: 'Access Requests', to: '/admin/access-requests', icon: KeyRound, enabled: false },
    { label: 'Security Events', to: '/admin/security-events', icon: ShieldAlert, enabled: false },
    { label: 'Incidents', to: '/admin/incidents', icon: AlertTriangle, enabled: false },
    { label: 'Users', to: '/admin/users', icon: Users, enabled: false },
    { label: 'Resources', to: '/admin/resources', icon: Database, enabled: false },
  ];

  const navItems = isAdmin ? adminNavItems : employeeNavItems;

  return (
    <>
      {mobileOpen && (
        <div
          className="gnosis-sidebar-backdrop"
          onClick={onCloseMobile}
          aria-hidden="true"
        />
      )}

      <aside className={`gnosis-sidebar ${mobileOpen ? 'mobile-open' : ''}`}>
        <div className="gnosis-sidebar-header">
          <div className="gnosis-sidebar-brand-badge">
            <ShieldAlert />
          </div>
          <div className="gnosis-sidebar-brand-info">
            <h1 className="gnosis-sidebar-title">GNOSIS</h1>
            <p className="gnosis-sidebar-subtitle">Intelligent Data Security</p>
          </div>
        </div>

        <nav className="gnosis-sidebar-nav" aria-label="Main Navigation">
          {navItems.map((item) => {
            const Icon = item.icon;

            if (!item.enabled) {
              return (
                <div
                  key={item.label}
                  className="gnosis-nav-item disabled"
                  title="Page coming in a future update"
                >
                  <Icon className="gnosis-nav-item-icon" />
                  <span>{item.label}</span>
                  <span className="gnosis-nav-item-badge">Soon</span>
                </div>
              );
            }

            return (
              <NavLink
                key={item.label}
                to={item.to}
                end
                onClick={onCloseMobile}
                className={({ isActive }) =>
                  `gnosis-nav-item ${isActive ? 'active' : ''}`
                }
              >
                <Icon className="gnosis-nav-item-icon" />
                <span>{item.label}</span>
              </NavLink>
            );
          })}
        </nav>

        <div className="gnosis-sidebar-footer">
          {user && (
            <div className="gnosis-sidebar-user-block">
              <div className="gnosis-sidebar-avatar">
                <UserIcon style={{ width: '1rem', height: '1rem' }} />
              </div>
              <div className="gnosis-sidebar-user-info">
                <span className="gnosis-sidebar-user-name">{user.name}</span>
                <span className="gnosis-sidebar-user-email">{user.email}</span>
                <span className="gnosis-sidebar-role-tag">{user.role}</span>
              </div>
            </div>
          )}

          <button
            type="button"
            onClick={logout}
            className="gnosis-sidebar-signout-btn"
          >
            <LogOut style={{ width: '0.875rem', height: '0.875rem' }} />
            <span>Sign Out</span>
          </button>
        </div>
      </aside>
    </>
  );
}