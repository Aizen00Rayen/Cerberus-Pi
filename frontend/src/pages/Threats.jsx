import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client.js";
import SeverityBadge from "../components/SeverityBadge.jsx";

export default function Threats() {
  const qc = useQueryClient();
  const [filters, setFilters] = useState({ severity: "", engine: "", search: "" });
  const [selected, setSelected] = useState(null);

  const { data, isLoading } = useQuery({
    queryKey: ["threats", filters],
    queryFn: async () => {
      const params = {};
      if (filters.severity) params.severity = filters.severity;
      if (filters.engine) params.engine = filters.engine;
      if (filters.search) params.search = filters.search;
      return (await api.get("/threats/", { params })).data;
    },
    refetchInterval: 20000,
  });

  async function blockIp(t) {
    await api.post(`/threats/${t.id}/block/`);
    qc.invalidateQueries({ queryKey: ["threats"] });
    setSelected((s) => (s ? { ...s, is_blocked: true } : s));
  }

  const rows = data?.results || [];

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Threats</h1>

      <div className="flex flex-wrap gap-2">
        <select className="bg-panel2 rounded-lg px-3 py-1.5 text-sm border border-white/10"
          value={filters.severity} onChange={(e) => setFilters({ ...filters, severity: e.target.value })}>
          <option value="">All severities</option>
          {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((s) => <option key={s}>{s}</option>)}
        </select>
        <select className="bg-panel2 rounded-lg px-3 py-1.5 text-sm border border-white/10"
          value={filters.engine} onChange={(e) => setFilters({ ...filters, engine: e.target.value })}>
          <option value="">All engines</option>
          <option value="suricata">Suricata</option>
          <option value="snort">Snort</option>
        </select>
        <input className="bg-panel2 rounded-lg px-3 py-1.5 text-sm border border-white/10 flex-1 min-w-40"
          placeholder="Search signature…" value={filters.search}
          onChange={(e) => setFilters({ ...filters, search: e.target.value })} />
      </div>

      <div className="card p-0 overflow-hidden">
        <table className="w-full">
          <thead className="bg-panel2">
            <tr>
              <th className="th">Time</th><th className="th">Severity</th><th className="th">Category</th>
              <th className="th">Source</th><th className="th">Dest</th><th className="th">Signature</th>
            </tr>
          </thead>
          <tbody>
            {isLoading && <tr><td className="td" colSpan={6}>Loading…</td></tr>}
            {rows.map((t) => (
              <tr key={t.id} className="hover:bg-white/5 cursor-pointer" onClick={() => setSelected(t)}>
                <td className="td mono text-slate-400">{new Date(t.timestamp).toLocaleString()}</td>
                <td className="td"><SeverityBadge level={t.severity} /></td>
                <td className="td">{t.category || "—"}</td>
                <td className="td mono">{t.src_ip || "—"}</td>
                <td className="td mono">{t.dst_ip || "—"}</td>
                <td className="td truncate max-w-xs">{t.signature}</td>
              </tr>
            ))}
            {!isLoading && !rows.length && <tr><td className="td" colSpan={6}>No threats match.</td></tr>}
          </tbody>
        </table>
      </div>

      {selected && (
        <div className="fixed inset-0 bg-black/60 grid place-items-center z-50" onClick={() => setSelected(null)}>
          <div className="card w-[42rem] max-w-[90vw] space-y-3" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <SeverityBadge level={selected.severity} />
                <span className="font-semibold">{selected.category || "Threat"}</span>
              </div>
              <button className="text-slate-500" onClick={() => setSelected(null)}>✕</button>
            </div>
            <div className="text-sm">{selected.signature}</div>
            <div className="grid grid-cols-2 gap-2 text-sm">
              <Field k="Source" v={`${selected.src_ip}:${selected.src_port ?? ""}`} />
              <Field k="Dest" v={`${selected.dst_ip}:${selected.dst_port ?? ""}`} />
              <Field k="Protocol" v={selected.protocol} />
              <Field k="Engine" v={selected.engine} />
            </div>
            <div className="bg-panel2 rounded-lg p-3">
              <div className="text-xs uppercase text-cyan mb-1">AI Advice</div>
              <div className="text-sm">{selected.advice || "—"}</div>
            </div>
            <div className="flex gap-2">
              <button className="btn-danger" disabled={selected.is_blocked} onClick={() => blockIp(selected)}>
                {selected.is_blocked ? "IP Blocked" : "Block Source IP"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function Field({ k, v }) {
  return (
    <div>
      <span className="text-slate-500">{k}: </span>
      <span className="mono">{v}</span>
    </div>
  );
}
