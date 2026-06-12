import { Database, Code2, KeyRound, Waves } from "lucide-react";

const ICONS = { sqli: Database, xss: Code2, bruteforce: KeyRound, dos: Waves };
const LABELS = { sqli: "SQL Injection", xss: "Cross-Site Scripting", bruteforce: "Brute Force", dos: "DoS / DDoS" };

function Gauge({ value }) {
  const pct = value == null ? 0 : Math.round(value * 100);
  const r = 26, c = 2 * Math.PI * r;
  const off = c - (pct / 100) * c;
  return (
    <svg width="64" height="64" viewBox="0 0 64 64" className="-rotate-90">
      <circle cx="32" cy="32" r={r} fill="none" stroke="#ffffff15" strokeWidth="6" />
      <circle cx="32" cy="32" r={r} fill="none" stroke="#00d4ff" strokeWidth="6"
        strokeDasharray={c} strokeDashoffset={off} strokeLinecap="round" />
      <text x="32" y="34" transform="rotate(90 32 32)" textAnchor="middle"
        className="fill-slate-100 text-[13px] font-bold">{value == null ? "—" : `${pct}%`}</text>
    </svg>
  );
}

export default function ModelCard({ attack, model }) {
  const Icon = ICONS[attack] || Database;
  const status = model?.status || "untrained";
  const badge = status === "active" ? "badge-LOW" : status === "training" ? "badge-MEDIUM" : "badge-INFO";
  return (
    <div className="card flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Icon className="text-cyan" size={18} />
          <span className="font-semibold text-sm">{LABELS[attack]}</span>
        </div>
        <span className={`badge ${badge}`}>{status}</span>
      </div>
      <div className="flex items-center gap-4">
        <Gauge value={model?.accuracy} />
        <div className="text-xs space-y-1 text-slate-400">
          <div>F1: <span className="text-slate-100">{model?.f1_score != null ? model.f1_score.toFixed(2) : "—"}</span></div>
          <div>Version: <span className="text-slate-100">v{model?.version ?? "—"}</span></div>
          <div>Samples: <span className="text-slate-100">{model?.training_samples ?? "—"}</span></div>
        </div>
      </div>
      <div className="text-[11px] text-slate-500">
        {model?.trained_at ? `Trained ${new Date(model.trained_at).toLocaleString()}` : "Not yet trained"}
      </div>
    </div>
  );
}
