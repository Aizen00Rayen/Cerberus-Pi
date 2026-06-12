import { NavLink } from "react-router-dom";
import {
  Shield, LayoutDashboard, Bug, Radar, Archive, FileText, Settings as Cog, LogOut, BrainCircuit,
} from "lucide-react";
import { logout } from "../api/client.js";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/threats", label: "Threats", icon: Bug },
  { to: "/scanner", label: "Scanner", icon: Radar },
  { to: "/intelligence", label: "AI Intelligence", icon: BrainCircuit }, // Phase 11
  { to: "/logs", label: "Log Vault", icon: Archive },
  { to: "/reports", label: "Reports", icon: FileText },
  { to: "/settings", label: "Settings", icon: Cog },
];

export default function Layout({ children, user, onLogout }) {
  async function doLogout() {
    try { await logout(); } finally { onLogout(); }
  }
  return (
    <div className="min-h-screen flex">
      <aside className="w-60 shrink-0 bg-panel border-r border-white/5 flex flex-col">
        <div className="flex items-center gap-2 px-5 py-4 border-b border-white/5">
          <Shield className="text-cyan" size={26} />
          <div>
            <div className="font-bold tracking-wide">CERBERUS PI</div>
            <div className="text-[10px] text-slate-500">Yanova Solutions</div>
          </div>
        </div>
        <nav className="flex-1 p-3 space-y-1">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition ${
                  isActive ? "bg-cyan/15 text-cyan" : "text-slate-400 hover:bg-white/5"
                }`
              }
            >
              <Icon size={18} /> {label}
            </NavLink>
          ))}
        </nav>
        <div className="p-3 border-t border-white/5">
          <div className="text-xs text-slate-500 px-3 mb-2">
            {user?.username || "admin"}
          </div>
          <button onClick={doLogout} className="flex items-center gap-2 text-sm text-slate-400 hover:text-alert px-3">
            <LogOut size={16} /> Sign out
          </button>
        </div>
      </aside>
      <main className="flex-1 overflow-auto">
        <div className="p-6 max-w-7xl mx-auto">{children}</div>
      </main>
    </div>
  );
}
