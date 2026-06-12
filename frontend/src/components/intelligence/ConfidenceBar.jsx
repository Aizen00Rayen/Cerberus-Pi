// Colored confidence bar (Phase 11.7): ≥90% red, 70–89% orange, 50–69% yellow.
export default function ConfidenceBar({ value }) {
  const pct = Math.round((value || 0) * 100);
  const color = pct >= 90 ? "bg-sev-critical" : pct >= 70 ? "bg-sev-high" : pct >= 50 ? "bg-sev-medium" : "bg-sev-low";
  return (
    <div className="flex items-center gap-2 min-w-[90px]">
      <div className="flex-1 h-2 rounded bg-white/10 overflow-hidden">
        <div className={`h-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs tabular-nums w-9 text-right">{pct}%</span>
    </div>
  );
}
