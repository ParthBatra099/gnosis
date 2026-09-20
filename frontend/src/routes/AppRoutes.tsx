import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { ProtectedRoute } from './ProtectedRoute';
import { EmployeeLayout } from '../layouts/EmployeeLayout';
import { AdminLayout } from '../layouts/AdminLayout';
import { Login } from '../pages/auth/Login';
import { EmployeeHome } from '../pages/employee/EmployeeHome';
import { AskGnosis } from '../pages/employee/AskGnosis';
import { AdminHome } from '../pages/admin/AdminHome';

function RootRedirect() {
  const { user, isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center font-mono">
        <div className="flex flex-col items-center gap-3">
          <div className="w-8 h-8 rounded-full border-2 border-cyan-500 border-t-transparent animate-spin" />
          <p className="text-xs text-slate-400 tracking-wider">LOADING GNOSIS...</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated || !user) {
    return <Navigate to="/login" replace />;
  }

  if (user.role.toUpperCase() === 'ADMIN') {
    return <Navigate to="/admin" replace />;
  }

  return <Navigate to="/employee" replace />;
}

// Picks the existing layout that matches the signed-in user's role, so pages
// shared by every authenticated user keep the admin or employee shell.
function SharedLayout() {
  const { user } = useAuth();
  const isAdmin = user?.role?.toUpperCase() === 'ADMIN';

  return isAdmin ? <AdminLayout /> : <EmployeeLayout />;
}

export function AppRoutes() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<RootRedirect />} />
        <Route path="/login" element={<Login />} />

        {/* Shared routes: any authenticated user (ADMIN or EMPLOYEE) */}
        <Route
          element={
            <ProtectedRoute>
              <SharedLayout />
            </ProtectedRoute>
          }
        >
          <Route path="/ask-gnosis" element={<AskGnosis />} />
        </Route>

        {/* Employee Shell Route Hierarchy */}
        <Route
          path="/employee"
          element={
            <ProtectedRoute>
              <EmployeeLayout />
            </ProtectedRoute>
          }
        >
          <Route index element={<EmployeeHome />} />
          <Route path="ask" element={<Navigate to="/ask-gnosis" replace />} />
        </Route>

        {/* Admin Shell Route Hierarchy */}
        <Route
          path="/admin"
          element={
            <ProtectedRoute allowedRoles={['ADMIN']}>
              <AdminLayout />
            </ProtectedRoute>
          }
        >
          <Route index element={<AdminHome />} />
        </Route>

        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}