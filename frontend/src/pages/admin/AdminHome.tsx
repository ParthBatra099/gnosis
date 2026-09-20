import { useAuth } from '../../hooks/useAuth';

export function AdminHome() {
  const { user, logout } = useAuth();

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col items-center justify-center p-6 font-sans">
      <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-6">
        <div className="border-b border-slate-800 pb-4">
          <h1 className="text-xl font-bold font-mono tracking-wide text-cyan-400">GNOSIS</h1>
          <p className="text-xs uppercase tracking-widest text-slate-400 mt-1 font-mono">
            Security Administration
          </p>
        </div>

        {user && (
          <div className="space-y-3 text-xs font-mono bg-slate-950/60 p-4 rounded-lg border border-slate-800/80">
            <div>
              <span className="text-slate-500 block text-[10px] uppercase">Admin Name</span>
              <span className="text-slate-200 font-medium">{user.name}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px] uppercase">Email</span>
              <span className="text-slate-200">{user.email}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px] uppercase">Role</span>
              <span className="inline-block px-2 py-0.5 mt-1 text-[10px] rounded bg-purple-500/10 border border-purple-500/30 text-purple-400 uppercase font-semibold">
                {user.role}
              </span>
            </div>
          </div>
        )}

        <div className="p-3 bg-slate-800/40 border border-slate-700/50 rounded-lg text-center">
          <p className="text-xs text-slate-400">
            Security console and admin controls coming in Chunk 5.
          </p>
        </div>

        <button
          onClick={logout}
          className="w-full py-2.5 px-4 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-mono font-semibold rounded-lg transition-colors cursor-pointer"
        >
          Sign Out
        </button>
      </div>
    </div>
  );
}