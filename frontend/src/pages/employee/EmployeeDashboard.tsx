import React from 'react';
import { LayoutDashboard, Lock } from 'lucide-react';

export const EmployeeDashboard: React.FC = () => {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-slate-100 font-mono tracking-tight">
          GNOSIS Employee Dashboard
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Personal resource access portal and access request hub.
        </p>
      </div>

      <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
        <div className="flex items-center gap-3 text-cyan-400">
          <LayoutDashboard className="w-5 h-5" />
          <h2 className="text-sm font-semibold text-slate-200">Employee Shell Active</h2>
        </div>
        <p className="text-xs text-slate-400 leading-relaxed max-w-2xl">
          Welcome to the employee access console. View permitted company resources and manage access requests.
        </p>
        <div className="pt-2 flex items-center gap-2 text-[11px] text-slate-500 font-mono">
          <Lock className="w-3.5 h-3.5" />
          <span>Access Level: Standard Granted</span>
        </div>
      </div>
    </div>
  );
};