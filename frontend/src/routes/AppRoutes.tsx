import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';

import { useAuth } from '../hooks/useAuth';
import { ProtectedRoute } from './ProtectedRoute';

import { EmployeeLayout } from '../layouts/EmployeeLayout';
import { AdminLayout } from '../layouts/AdminLayout';

import { Login } from '../pages/auth/Login';

import { EmployeeHome } from '../pages/employee/EmployeeHome';
import { AskGnosis } from '../pages/employee/AskGnosis';

import { AdminDashboard } from '../pages/admin/AdminDashboard';


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

  if (user.role?.toUpperCase() === 'ADMIN') {
    return (
      <Navigate
        to="/admin"
        replace
      />
    );
  }

  return (
    <Navigate
      to="/employee"
      replace
    />
  );
}


/* =========================================================
   SHARED LAYOUT
   ========================================================= */

function SharedLayout() {
  const { user } = useAuth();

  const isAdmin =
    user?.role?.toUpperCase() === 'ADMIN';

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
              allowedRoles={['ADMIN']}
            >
              <AdminLayout />
            </ProtectedRoute>
          }
        >

          {/* Admin Dashboard */}

          <Route
            index
            element={<AdminDashboard />}
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