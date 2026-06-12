import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client.js";

export default function Reports() {
  const qc = useQueryClient();
  const today = new Date().toISOString().slice(0, 10);
  const [form, setForm] = useState({
    title: "Cerberus Threat Report",
    report_type: "daily",
    period_start: `${today}T00:00`,
    period_end: `${today}T23:59`,
  });

  const { data } = useQuery({
    queryKey: ["reports"],
    queryFn: async () => (await api.get("/reports/")).data,
    refetchInterval: 8000,
  });

  async function generate() {
    await api.post("/reports/generate/", {
      ...form,
      period_start: new Date(form.period_start).toISOString(),
      period_end: new Date(form.period_end).toISOString(),
    });
    qc.invalidateQueries({ queryKey: ["reports"] });
  }

  const rows = data?.results || [];

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold">Reports</h1>

      <div className="card grid md:grid-cols-2 gap-3">
        <Input label="Title" value={form.title} onChange={(v) => setForm({ ...form, title: v })} />
        <div>
          <label className="text-xs text-slate-500 block mb-1">Type</label>
          <select className="w-full bg-panel2 rounded-lg px-3 py-1.5 text-sm border border-white/10"
            value={form.report_type} onChange={(e) => setForm({ ...form, report_type: e.target.value })}>
            {["daily", "weekly", "monthly", "custom"].map((t) => <option key={t}>{t}</option>)}
          </select>
        </div>
        <Input label="Period start" type="datetime-local" value={form.period_start}
          onChange={(v) => setForm({ ...form, period_start: v })} />
        <Input label="Period end" type="datetime-local" value={form.period_end}
          onChange={(v) => setForm({ ...form, period_end: v })} />
        <div className="md:col-span-2"><button className="btn" onClick={generate}>Generate PDF</button></div>
      </div>

      <div className="card p-0 overflow-hidden">
        <table className="w-full">
          <thead className="bg-panel2"><tr>
            <th className="th">Title</th><th className="th">Type</th><th className="th">Status</th>
            <th className="th">SHA-256</th><th className="th"></th>
          </tr></thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id} className="hover:bg-white/5">
                <td className="td">{r.title}</td>
                <td className="td">{r.report_type}</td>
                <td className="td">{r.status}</td>
                <td className="td mono truncate max-w-[12rem]">{r.sha256 || "—"}</td>
                <td className="td">
                  {r.status === "done"
                    ? <a className="btn" href={`/api/reports/${r.id}/download/`}>Download</a>
                    : <span className="text-slate-600 text-xs">{r.status}…</span>}
                </td>
              </tr>
            ))}
            {!rows.length && <tr><td className="td" colSpan={5}>No reports yet.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Input({ label, value, onChange, type = "text" }) {
  return (
    <div>
      <label className="text-xs text-slate-500 block mb-1">{label}</label>
      <input type={type} className="w-full bg-panel2 rounded-lg px-3 py-1.5 text-sm border border-white/10"
        value={value} onChange={(e) => onChange(e.target.value)} />
    </div>
  );
}
