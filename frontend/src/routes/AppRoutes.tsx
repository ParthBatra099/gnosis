import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';

import { useAuth } from '../hooks/useAuth';
import { ProtectedRoute } from './ProtectedRoute';
import { getDefaultRouteForUser, isAdministrator } from '../utils/roles';

import { EmployeeLayout } from '../layouts/EmployeeLayout';
import { AdminLayout } from '../layouts/AdminLayout';

import { Login } from '../pages/auth/Login';
import { SessionManagement } from '../pages/auth/SessionManagement';

import { EmployeeHome } from '../pages/employee/EmployeeHome';
import { AskGnosis } from '../pages/employee/AskGnosis';

import { AdminDashboard } from '../pages/admin/AdminDashboard';
import { SecurityEvents } from '../pages/admin/SecurityEvents';
import { Incidents } from '../pages/admin/Incidents';
import { AuditLogs } from '../pages/admin/AuditLogs';
import { SecurityTimeline } from '../pages/admin/SecurityTimeline';
import { OrganizationPage } from '../pages/admin/OrganizationPage';
import { AccessRequests as EmployeeAccessRequests } from '../pages/employee/AccessRequests';
import { AccessRequests as AdminAccessRequests } from '../pages/admin/AccessRequests';

/* =========================================================
   ROOT REDIRECT
   ========================================================= */

function RootRedirect() {
  const {
    user,
    isAuthenticated,
    isLoading,
  } = useAuth();

  if (isLoading) {
    return (
      <div className="gnosis-route-loading">
        <div className="gnosis-route-loading-spinner" />
        <p>LOADING GNOSIS...</p>
      </div>
    );
  }

  if (!isAuthenticated || !user) {
    return (
      <Navigate
        to="/login"
        replace
      />
    );
  }

  return <Navigate to={getDefaultRouteForUser(user)} replace />;
}


/* =========================================================
   SHARED LAYOUT
   ========================================================= */

function IdentityUnavailable() {
  const { user, isAuthenticated, isLoading, logout } = useAuth();
  if (isLoading) return <p>Verifying session…</p>;
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  if (getDefaultRouteForUser(user) !== '/identity-unavailable') return <Navigate to="/" replace />;
  return <main className="gnosis-auth-panel"><section><h1>Organizational identity unavailable</h1>
    <p>No recognized canonical role was returned. Role-specific navigation is unavailable. Contact your organization’s identity administrator.</p>
    <button type="button" onClick={() => void logout()}>Sign out</button></section></main>;
}

function SharedLayout() {
  const { user } = useAuth();

  const isAdmin = isAdministrator(user);

  return isAdmin
    ? <AdminLayout />
    : <EmployeeLayout />;
}


/* =========================================================
   APP ROUTES
   ========================================================= */

export function AppRoutes() {
  return (
    <BrowserRouter>

      <Routes>
        <Route path="/identity-unavailable" element={<IdentityUnavailable />} />

        {/* =================================================
            ROOT
            ================================================= */}

        <Route
          path="/"
          element={<RootRedirect />}
        />


        {/* =================================================
            LOGIN
            ================================================= */}

        <Route
          path="/login"
          element={<Login />}
        />


        {/* =================================================
            SHARED AUTHENTICATED PAGES
            ================================================= */}

        <Route
          element={
            <ProtectedRoute>
              <SharedLayout />
            </ProtectedRoute>
          }
        >

          <Route
            path="/ask-gnosis"
            element={<AskGnosis />}
          />
          <Route path="/sessions" element={<SessionManagement />} />

        </Route>


        {/* =================================================
            EMPLOYEE
            ================================================= */}

        <Route
          path="/employee"
          element={
            <ProtectedRoute>
              <EmployeeLayout />
            </ProtectedRoute>
          }
        >

          {/* Employee Overview */}

          <Route
            index
            element={<EmployeeHome />}
          />
          <Route
  path="access-requests"
  element={<EmployeeAccessRequests />}
/>


          {/* Legacy employee/ask URL */}

          <Route
            path="ask"
            element={
              <Navigate
                to="/ask-gnosis"
                replace
              />
            }
          />

        </Route>


        {/* =================================================
            ADMIN
            ================================================= */}

        <Route
          path="/admin"
          element={
            <ProtectedRoute
              allowedRoles={['SUPER_ADMIN', 'DEPARTMENT_ADMIN']}
            >
              <AdminLayout />
            </ProtectedRoute>
          }
        >

          {/* Admin Dashboard */}
          <Route path="security-events" element={<SecurityEvents />} />
          <Route path="incidents" element={<Incidents />} />
          <Route path="audit-logs" element={<AuditLogs />} />
          <Route path="timeline" element={<SecurityTimeline />} />
          <Route path="departments" element={<OrganizationPage section="departments" />} />
          <Route path="employees" element={<OrganizationPage section="employees" />} />
          <Route path="employees/:userId/sessions" element={<ProtectedRoute allowedRoles={['SUPER_ADMIN']}><SessionManagement /></ProtectedRoute>} />
          <Route path="assignments" element={<ProtectedRoute allowedRoles={['SUPER_ADMIN']}><OrganizationPage section="assignments" /></ProtectedRoute>} />

          <Route
            index
            element={<AdminDashboard />}
          />
          <Route
  path="access-requests"
  element={<AdminAccessRequests />}
/>

        </Route>


        {/* =================================================
            FALLBACK
            ================================================= */}

        <Route
          path="*"
          element={
            <Navigate
              to="/"
              replace
            />
          }
        />

      </Routes>

    </BrowserRouter>
  );
}
