import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldCheck, ShieldAlert } from "lucide-react";
import { api } from "../api/client.js";

export default function LogVault() {
  const qc = useQueryClient();
  const [day, setDay] = useState(null);

  const { data: archives } = useQuery({
    queryKey: ["archives"],
    queryFn: async () => (await api.get("/logs/daily/")).data,
    refetchInterval: 30000,
  });

  const { data: entries } = useQuery({
    queryKey: ["log-entries", day],
    enabled: !!day,
    queryFn: async () => (await api.get(`/logs/entries/by-date/${day}/`)).data,
  });

  async function verify(id) {
    await api.post(`/logs/daily/${id}/verify/`);
    qc.invalidateQueries({ queryKey: ["archives"] });
  }

  const rows = archives?.results || [];
  const logRows = entries?.results || entries || [];

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold">Log Vault</h1>
      <p className="text-sm text-slate-500">
        Daily archives are pinned to a private IPFS node with SHA-256 integrity hashes.
      </p>

      <div className="card p-0 overflow-hidden">
        <table className="w-full">
          <thead className="bg-panel2"><tr>
            <th className="th">Date</th><th className="th">Entries</th><th className="th">IPFS CID</th>
            <th className="th">Integrity</th><th className="th"></th>
          </tr></thead>
          <tbody>
            {rows.map((a) => (
              <tr key={a.id} className="hover:bg-white/5">
                <td className="td">
                  <button className="text-cyan underline" onClick={() => setDay(a.date)}>{a.date}</button>
                </td>
                <td className="td">{a.log_count}</td>
                <td className="td mono truncate max-w-[14rem]">{a.ipfs_cid || "—"}</td>
                <td className="td">
                  {a.verified
                    ? <span className="flex items-center gap-1 text-green-400"><ShieldCheck size={16}/>Verified</span>
                    : <span className="flex items-center gap-1 text-slate-500"><ShieldAlert size={16}/>Unverified</span>}
                </td>
                <td className="td"><button className="btn" onClick={() => verify(a.id)}>Verify</button></td>
              </tr>
            ))}
            {!rows.length && <tr><td className="td" colSpan={5}>No archives yet.</td></tr>}
          </tbody>
        </table>
      </div>

      {day && (
        <div className="card">
          <div className="flex items-center justify-between mb-3">
            <h2 className="font-semibold">Logs for {day}</h2>
            <button className="text-slate-500" onClick={() => setDay(null)}>close</button>
          </div>
          <div className="space-y-1 max-h-96 overflow-auto mono">
            {logRows.map((l) => (
              <div key={l.id} className="flex gap-3 text-xs py-1 border-b border-white/5">
                <span className="text-slate-600">{new Date(l.created_at).toLocaleTimeString()}</span>
                <span className="text-cyan w-16">{l.level}</span>
                <span className="text-slate-500 w-20">{l.source}</span>
                <span className="flex-1">{l.message}</span>
              </div>
            ))}
            {!logRows.length && <div className="text-slate-600 text-sm">No entries.</div>}
          </div>
        </div>
      )}
    </div>
  );
}
