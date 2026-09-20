import React from 'react';
import { Shield, Server } from 'lucide-react';

export const AdminDashboard: React.FC = () => {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-slate-100 font-mono tracking-tight">
          GNOSIS Security Console
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Centralized administrative monitoring and security control center.
        </p>
      </div>

      <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
        <div className="flex items-center gap-3 text-cyan-400">
          <Shield className="w-5 h-5" />
          <h2 className="text-sm font-semibold text-slate-200">Security Shell Verified</h2>
        </div>
        <p className="text-xs text-slate-400 leading-relaxed max-w-2xl">
          The administrative environment shell is active. Connected to security monitoring APIs and role authorization guards.
        </p>
        <div className="pt-2 flex items-center gap-2 text-[11px] text-slate-500 font-mono">
          <Server className="w-3.5 h-3.5" />
          <span>Status: Operational</span>
        </div>
      </div>
    </div>
  );
};