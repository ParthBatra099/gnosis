import { useState } from 'react';
import { Outlet } from 'react-router-dom';
import { Sidebar } from '../components/layout/Sidebar';
import { Topbar } from '../components/layout/Topbar';
import '../styles/shell.css';

export function AdminLayout() {
  const [mobileOpen, setMobileOpen] = useState<boolean>(false);

  const toggleMobile = () => setMobileOpen((prev) => !prev);
  const closeMobile = () => setMobileOpen(false);

  return (
    <div className="gnosis-shell">
      <Sidebar mobileOpen={mobileOpen} onCloseMobile={closeMobile} />
      <div className="gnosis-main-wrapper">
        <Topbar pageTitle="Security Console" onToggleMobile={toggleMobile} />
        <main className="gnosis-content-area">
          <Outlet />
        </main>
      </div>
    </div>
  );
}