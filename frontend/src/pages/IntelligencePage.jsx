import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell, LineChart, Line,
  XAxis, YAxis, Tooltip, CartesianGrid, Legend,
} from "recharts";
import { RefreshCw, Sliders } from "lucide-react";
import { api, openSocket } from "../api/client.js";
import ModelCard from "../components/intelligence/ModelCard.jsx";
import DetectionFeed from "../components/intelligence/DetectionFeed.jsx";

const ATTACKS = ["sqli", "xss", "bruteforce", "dos"];
const PIE_COLORS = { confirmed: "#ff7700", false_positive: "#7a8699", pending: "#00d4ff" };

export default function IntelligencePage() {
  const qc = useQueryClient();
  const [liveRows, setLiveRows] = useState([]);
  const [confirmRetrain, setConfirmRetrain] = useState(false);
  const [showThresholds, setShowThresholds] = useState(false);

  const { data: models } = useQuery({
    queryKey: ["ml-models"],
    queryFn: async () => (await api.get("/intelligence/models/")).data,
    refetchInterval: 10000,
  });
  const { data: baseline } = useQuery({
    queryKey: ["ml-baseline"],
    queryFn: async () => (await api.get("/intelligence/baseline/status/")).data,
    refetchInterval: 30000,
  });
  const { data: stats } = useQuery({
    queryKey: ["ml-stats"],
    queryFn: async () => (await api.get("/intelligence/stats/")).data,
    refetchInterval: 15000,
  });
  const { data: detections } = useQuery({
    queryKey: ["ml-detections"],
    queryFn: async () => (await api.get("/intelligence/detections/")).data,
    refetchInterval: 20000,
  });
  const { data: jobs } = useQuery({
    queryKey: ["ml-jobs"],
    queryFn: async () => (await api.get("/intelligence/training/")).data,
    refetchInterval: 15000,
  });

  // Live anomaly stream.
  useEffect(() => {
    const close = openSocket("/ws/intelligence/", (msg) => {
      if (msg.event === "anomaly") setLiveRows((r) => [msg.data, ...r].slice(0, 50));
    });
    return close;
  }, []);

  // Merge live + fetched detections (live first, dedup by id).
  const fetched = detections?.results || [];
  const seen = new Set(liveRows.map((r) => r.id));
  const feedRows = [...liveRows, ...fetched.filter((r) => !seen.has(r.id))].slice(0, 50);

  const activeByType = {};
  (models?.results || []).forEach((m) => {
    if (m.status === "active") activeByType[m.attack_type] = m;
  });

  async function verdict(d, v) {
    await api.post(`/intelligence/detections/${d.id}/verdict/`, { verdict: v });
    setLiveRows((rows) => rows.map((r) => (r.id === d.id ? { ...r, verdict: v } : r)));
    qc.invalidateQueries({ queryKey: ["ml-detections"] });
    qc.invalidateQueries({ queryKey: ["ml-stats"] });
  }

  async function retrain() {
    await api.post("/intelligence/models/retrain/", { attack_type: "all" });
    setConfirmRetrain(false);
    qc.invalidateQueries({ queryKey: ["ml-jobs"] });
  }

  // Baseline pill.
  let pill = { text: "🟢 Active", cls: "badge-LOW" };
  if (baseline && !baseline.complete) {
    pill = { text: `🟡 Learning (${baseline.remaining_hours}h left)`, cls: "badge-MEDIUM" };
  } else if (!Object.keys(activeByType).length) {
    pill = { text: "🔴 Models Outdated", cls: "badge-CRITICAL" };
  }

  const typeChart = ATTACKS.map((a) => ({
    name: a.toUpperCase(), count: stats?.detections_7d_by_type?.[a] || 0,
  }));
  const verdictChart = Object.entries(stats?.verdict_breakdown || {}).map(([k, v]) => ({ name: k, value: v }));
  const accuracyChart = (models?.results || [])
    .filter((m) => m.accuracy != null)
    .sort((a, b) => a.version - b.version)
    .map((m) => ({ name: `${m.attack_type} v${m.version}`, accuracy: Math.round(m.accuracy * 100) }));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h1 className="text-xl font-semibold">AI Intelligence</h1>
        <div className="flex items-center gap-3">
          <span className={`badge ${pill.cls}`}>{pill.text}</span>
          <button className="btn flex items-center gap-1" onClick={() => setConfirmRetrain(true)}>
            <RefreshCw size={15} /> Retrain Now
          </button>
        </div>
      </div>

      {/* Model cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {ATTACKS.map((a) => <ModelCard key={a} attack={a} model={activeByType[a]} />)}
      </div>

      {/* Baseline progress (only during baseline phase) */}
      {baseline && !baseline.complete && (
        <div className="card">
          <div className="flex items-center justify-between mb-2">
            <h2 className="font-semibold">Baseline Learning</h2>
            <span className="text-xs text-slate-500">
              {baseline.progress_percent}% · {baseline.profiles} IPs profiled
            </span>
          </div>
          <div className="h-3 rounded bg-white/10 overflow-hidden">
            <div className="h-full bg-cyan" style={{ width: `${baseline.progress_percent}%` }} />
          </div>
          <p className="text-xs text-slate-500 mt-2">
            AI is learning your network. Detection runs in fallback mode until the {baseline.total_hours}h
            baseline completes.
          </p>
        </div>
      )}

      {/* Live detection feed */}
      <DetectionFeed rows={feedRows} onVerdict={verdict} />

      {/* Stats panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="card">
          <h2 className="font-semibold mb-3 text-sm">Detections by type (7d)</h2>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={typeChart}>
              <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" />
              <XAxis dataKey="name" stroke="#7a8699" fontSize={11} />
              <YAxis stroke="#7a8699" fontSize={11} allowDecimals={false} />
              <Tooltip contentStyle={{ background: "#16233d", border: "none", borderRadius: 8 }} />
              <Bar dataKey="count" fill="#00d4ff" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
        <div className="card">
          <h2 className="font-semibold mb-3 text-sm">Model accuracy by version</h2>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={accuracyChart}>
              <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" />
              <XAxis dataKey="name" stroke="#7a8699" fontSize={10} />
              <YAxis stroke="#7a8699" fontSize={11} domain={[0, 100]} />
              <Tooltip contentStyle={{ background: "#16233d", border: "none", borderRadius: 8 }} />
              <Line type="monotone" dataKey="accuracy" stroke="#00d4ff" strokeWidth={2} dot />
            </LineChart>
          </ResponsiveContainer>
        </div>
        <div className="card">
          <h2 className="font-semibold mb-3 text-sm">Verdict breakdown</h2>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={verdictChart} dataKey="value" nameKey="name" outerRadius={70} label>
                {verdictChart.map((e) => <Cell key={e.name} fill={PIE_COLORS[e.name] || "#888"} />)}
              </Pie>
              <Legend />
              <Tooltip contentStyle={{ background: "#16233d", border: "none", borderRadius: 8 }} />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Threshold panel */}
      <ThresholdPanel show={showThresholds} onToggle={() => setShowThresholds(!showThresholds)} />

      {/* Training history */}
      <div className="card p-0 overflow-hidden">
        <div className="p-3 font-semibold">Training History</div>
        <table className="w-full">
          <thead className="bg-panel2"><tr>
            <th className="th">Date</th><th className="th">Model</th><th className="th">Trigger</th>
            <th className="th">Duration</th><th className="th">Status</th>
          </tr></thead>
          <tbody>
            {(jobs?.results || []).map((j) => (
              <tr key={j.id} className="hover:bg-white/5">
                <td className="td mono text-slate-400">{new Date(j.created_at).toLocaleString()}</td>
                <td className="td">{j.attack_type}</td>
                <td className="td">{j.triggered_by}</td>
                <td className="td">{j.duration_seconds != null ? `${j.duration_seconds}s` : "—"}</td>
                <td className="td">{j.status}</td>
              </tr>
            ))}
            {!(jobs?.results || []).length && <tr><td className="td text-slate-600" colSpan={5}>No training jobs yet.</td></tr>}
          </tbody>
        </table>
      </div>

      {/* Retrain confirmation modal */}
      {confirmRetrain && (
        <div className="fixed inset-0 bg-black/60 grid place-items-center z-50" onClick={() => setConfirmRetrain(false)}>
          <div className="card w-96 space-y-4" onClick={(e) => e.stopPropagation()}>
            <h2 className="font-semibold">Retrain all models?</h2>
            <p className="text-sm text-slate-400">
              This queues training jobs for all four detectors using bundled datasets plus
              admin-confirmed feedback. It runs on the isolated intelligence worker and may take
              a few minutes on the Pi.
            </p>
            <div className="flex justify-end gap-2">
              <button className="btn" onClick={() => setConfirmRetrain(false)}>Cancel</button>
              <button className="btn-danger" onClick={retrain}>Retrain</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function ThresholdPanel({ show, onToggle }) {
  const qc = useQueryClient();
  const [values, setValues] = useState(null);
  const { data } = useQuery({
    queryKey: ["ml-thresholds"],
    queryFn: async () => (await api.get("/intelligence/thresholds/")).data,
    enabled: show,
  });
  useEffect(() => { if (data && !values) setValues(data); }, [data]); // eslint-disable-line

  async function save() {
    await api.post("/intelligence/thresholds/", values);
    qc.invalidateQueries({ queryKey: ["ml-thresholds"] });
  }

  const SLIDERS = [
    { key: "sqli", label: "SQLi confidence", min: 0.3, max: 0.95, step: 0.05 },
    { key: "xss", label: "XSS confidence", min: 0.3, max: 0.95, step: 0.05 },
    { key: "dos_pps", label: "DoS PPS multiplier", min: 1.5, max: 8, step: 0.5 },
    { key: "dos_syn_ratio", label: "SYN/ACK ratio", min: 2, max: 30, step: 1 },
  ];

  return (
    <div className="card">
      <button className="flex items-center gap-2 font-semibold" onClick={onToggle}>
        <Sliders size={16} className="text-cyan" /> Threshold Settings
        <span className="text-xs text-slate-500">({show ? "hide" : "show"})</span>
      </button>
      {show && values && (
        <div className="mt-4 space-y-4">
          {SLIDERS.map((s) => (
            <div key={s.key}>
              <div className="flex justify-between text-sm mb-1">
                <span className="text-slate-400">{s.label}</span>
                <span className="mono text-cyan">{values[s.key]}</span>
              </div>
              <input type="range" min={s.min} max={s.max} step={s.step} value={values[s.key] ?? s.min}
                onChange={(e) => setValues({ ...values, [s.key]: parseFloat(e.target.value) })}
                className="w-full accent-cyan" />
            </div>
          ))}
          <p className="text-xs text-slate-500">
            Lower confidence thresholds = more sensitive (more alerts, more false positives).
          </p>
          <button className="btn" onClick={save}>Save thresholds</button>
        </div>
      )}
    </div>
  );
}
