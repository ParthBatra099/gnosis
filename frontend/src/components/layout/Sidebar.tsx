import type { ElementType } from 'react';
import { NavLink } from 'react-router-dom';

import {
  ShieldCheck,
  LayoutDashboard,
  Users,
  Database,
  KeyRound,
  AlertTriangle,
  MessageSquare,
  LogOut,
  User as UserIcon,
  ChevronRight,
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


export function Sidebar({
  mobileOpen,
  onCloseMobile,
}: SidebarProps) {

  const { user, logout } = useAuth();

  const isAdmin =
    user?.role?.toUpperCase() === 'ADMIN';


  /* =====================================================
     EMPLOYEE NAVIGATION
     ===================================================== */

  const employeeNavItems: NavItem[] = [
    {
      label: 'Overview',
      to: '/employee',
      icon: LayoutDashboard,
      enabled: true,
    },
    {
      label: 'Ask GNOSIS',
      to: '/ask-gnosis',
      icon: MessageSquare,
      enabled: true,
    },
    {
      label: 'Resources',
      to: '/employee/resources',
      icon: Database,
      enabled: false,
    },
    {
      label: 'Access Requests',
      to: '/employee/access-requests',
      icon: KeyRound,
      enabled: false,
    },
  ];


  /* =====================================================
     ADMIN NAVIGATION
     ===================================================== */

  const adminNavItems: NavItem[] = [
    {
      label: 'Overview',
      to: '/admin',
      icon: LayoutDashboard,
      enabled: true,
    },
    {
      label: 'Ask GNOSIS',
      to: '/ask-gnosis',
      icon: MessageSquare,
      enabled: true,
    },
    {
      label: 'Access Requests',
      to: '/admin/access-requests',
      icon: KeyRound,
      enabled: false,
    },
    {
      label: 'Security Events',
      to: '/admin/security-events',
      icon: ShieldCheck,
      enabled: false,
    },
    {
      label: 'Incidents',
      to: '/admin/incidents',
      icon: AlertTriangle,
      enabled: false,
    },
    {
      label: 'Users',
      to: '/admin/users',
      icon: Users,
      enabled: false,
    },
    {
      label: 'Resources',
      to: '/admin/resources',
      icon: Database,
      enabled: false,
    },
  ];


  const navItems =
    isAdmin
      ? adminNavItems
      : employeeNavItems;


  return (
    <>
      {/* Mobile backdrop */}

      {mobileOpen && (
        <div
          className="gnosis-sidebar-backdrop"
          onClick={onCloseMobile}
          aria-hidden="true"
        />
      )}


      <aside
        className={`gnosis-sidebar ${mobileOpen ? 'mobile-open' : ''
          }`}
      >

        {/* =================================================
            BRAND
            ================================================= */}

        <div className="gnosis-sidebar-header">

          <div className="gnosis-sidebar-logo">
            G
          </div>

          <div className="gnosis-sidebar-brand-info">

            <span className="gnosis-sidebar-title">
              GNOSIS
            </span>

            <span className="gnosis-sidebar-subtitle">
              Management System
            </span>

          </div>

        </div>


        {/* =================================================
            WORKSPACE
            ================================================= */}

        <div className="gnosis-sidebar-section-label">
          WORKSPACE
        </div>


        {/* =================================================
            NAVIGATION
            ================================================= */}

        <nav
          className="gnosis-sidebar-nav"
          aria-label="Main Navigation"
        >

          {navItems.map((item) => {

            const Icon = item.icon;


            /*
             * Disabled navigation item
             */

            if (!item.enabled) {
              return (
                <div
                  key={item.label}
                  className="gnosis-nav-item disabled"
                  title="This section is not available yet"
                >

                  <Icon
                    className="gnosis-nav-item-icon"
                  />

                  <span>
                    {item.label}
                  </span>

                </div>
              );
            }


            /*
             * Active navigation item
             */

            return (
              <NavLink
                key={item.label}
                to={item.to}
                end
                onClick={onCloseMobile}
                className={({ isActive }) =>
                  `gnosis-nav-item ${isActive ? 'active' : ''
                  }`
                }
              >

                <Icon
                  className="gnosis-nav-item-icon"
                />

                <span>
                  {item.label}
                </span>

                <ChevronRight
                  className="gnosis-nav-arrow"
                />

              </NavLink>
            );

          })}

        </nav>


        {/* =================================================
            USER AREA
            ================================================= */}

        <div className="gnosis-sidebar-footer">

          {user && (
            <div className="gnosis-sidebar-user-block">

              <div className="gnosis-sidebar-avatar">
                <UserIcon />
              </div>

              <div className="gnosis-sidebar-user-info">

                <span className="gnosis-sidebar-user-name">
                  {user.name}
                </span>

                <span className="gnosis-sidebar-user-email">
                  {user.email}
                </span>

                <span className="gnosis-sidebar-role-tag">
                  {user.role}
                </span>

              </div>

            </div>
          )}


          {/* Sign out */}

          <button
            type="button"
            onClick={logout}
            className="gnosis-sidebar-signout-btn"
          >

            <LogOut />

            <span>
              Sign out
            </span>

          </button>

        </div>

      </aside>
    </>
  );
}