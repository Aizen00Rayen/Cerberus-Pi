import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid,
} from "recharts";
import { api, openSocket } from "../api/client.js";
import SeverityBadge from "../components/SeverityBadge.jsx";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export default function Dashboard() {
  const [liveFeed, setLiveFeed] = useState([]);
  const [engines, setEngines] = useState([]);

  const { data: summary } = useQuery({
    queryKey: ["threat-summary"],
    queryFn: async () => (await api.get("/threats/summary/")).data,
    refetchInterval: 15000,
  });

  // Live threat feed via WebSocket (Phase 6.3).
  useEffect(() => {
    const close = openSocket("/ws/threats/", (msg) => {
      if (msg.event === "threat") {
        setLiveFeed((f) => [msg.data, ...f].slice(0, 30));
        if (msg.data.severity === "CRITICAL") {
          // simple toast
          console.warn("CRITICAL threat:", msg.data.signature);
        }
      }
    });
    return close;
  }, []);

  // Live engine status.
  useEffect(() => {
    const close = openSocket("/ws/engine/", (msg) => {
      if (msg.event === "snapshot" || msg.event === "engine") setEngines(msg.data);
    });
    return close;
  }, []);

  const counts = summary?.by_severity || {};
  const chartData = SEVERITIES.map((s) => ({ name: s, count: counts[s] || 0 }));

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold">Operations Dashboard</h1>

      {/* Severity counters */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {SEVERITIES.map((s) => (
          <div key={s} className="stat">
            <SeverityBadge level={s} />
            <div className="text-3xl font-bold">{counts[s] || 0}</div>
            <div className="text-xs text-slate-500">total {s.toLowerCase()}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Live feed */}
        <div className="card lg:col-span-2">
          <div className="flex items-center justify-between mb-3">
            <h2 className="font-semibold">Live Threat Feed</h2>
            <span className="text-xs text-slate-500">{liveFeed.length} streaming</span>
          </div>
          <div className="space-y-1 max-h-80 overflow-auto">
            {liveFeed.length === 0 && (
              <div className="text-slate-500 text-sm py-8 text-center">
                Waiting for live alerts…
              </div>
            )}
            {liveFeed.map((t) => (
              <div key={t.id} className="flex items-center gap-3 text-sm py-1.5 border-b border-white/5">
                <SeverityBadge level={t.severity} />
                <span className="mono text-slate-400">{t.src_ip}→{t.dst_ip}</span>
                <span className="truncate flex-1">{t.signature}</span>
                <span className="text-[10px] text-slate-600">{t.engine}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Engine status */}
        <div className="card">
          <h2 className="font-semibold mb-3">Engines</h2>
          <div className="space-y-3">
            {(engines.length ? engines : [{ engine_name: "suricata" }, { engine_name: "snort" }]).map((e) => {
              const up = e.status === "running";
              return (
                <div key={e.engine_name} className="flex items-center justify-between">
                  <span className="flex items-center gap-2">
                    <span className={`w-2.5 h-2.5 rounded-full ${up ? "bg-green-400" : "bg-alert"}`} />
                    {e.engine_name}
                  </span>
                  <span className="text-xs text-slate-500">
                    {up ? `up ${Math.floor((e.uptime || 0) / 60)}m` : (e.status || "unknown")}
                  </span>
                </div>
              );
            })}
          </div>
          <h3 className="font-semibold mt-5 mb-2 text-sm">Top attackers (24h)</h3>
          <div className="space-y-1">
            {(summary?.top_attackers_24h || []).map((a) => (
              <div key={a.src_ip} className="flex justify-between text-sm">
                <span className="mono text-slate-400">{a.src_ip}</span>
                <span className="text-cyan">{a.count}</span>
              </div>
            ))}
            {!(summary?.top_attackers_24h || []).length && (
              <div className="text-slate-600 text-sm">None in last 24h</div>
            )}
          </div>
        </div>
      </div>

      {/* Severity chart */}
      <div className="card">
        <h2 className="font-semibold mb-3">Threats by Severity</h2>
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={chartData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" />
            <XAxis dataKey="name" stroke="#7a8699" fontSize={12} />
            <YAxis stroke="#7a8699" fontSize={12} allowDecimals={false} />
            <Tooltip contentStyle={{ background: "#16233d", border: "none", borderRadius: 8 }} />
            <Bar dataKey="count" fill="#00d4ff" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
