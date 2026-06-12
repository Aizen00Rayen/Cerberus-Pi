import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client.js";

const SCAN_TYPES = [
  ["discovery", "Host Discovery"], ["port", "Port Scan"], ["os", "OS Fingerprint"],
  ["vuln", "Vulnerability"], ["service", "Service Version"], ["stealth", "Stealth"],
  ["udp", "UDP"], ["arp", "ARP"],
];

function riskColor(score) {
  if (score >= 70) return "text-sev-critical";
  if (score >= 40) return "text-sev-high";
  if (score >= 20) return "text-sev-medium";
  return "text-sev-low";
}

export default function Scanner() {
  const qc = useQueryClient();
  const [scanType, setScanType] = useState("discovery");
  const [target, setTarget] = useState("localnet");

  const { data: hosts } = useQuery({
    queryKey: ["hosts"],
    queryFn: async () => (await api.get("/scanner/hosts/")).data,
    refetchInterval: 15000,
  });
  const { data: results } = useQuery({
    queryKey: ["scan-results"],
    queryFn: async () => (await api.get("/scanner/results/")).data,
    refetchInterval: 10000,
  });

  async function launch() {
    await api.post("/scanner/results/scan/", { scan_type: scanType, target });
    qc.invalidateQueries({ queryKey: ["scan-results"] });
  }

  const hostRows = hosts?.results || [];
  const scanRows = results?.results || [];

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold">Network Scanner</h1>

      <div className="card flex flex-wrap items-end gap-3">
        <div>
          <label className="text-xs text-slate-500 block mb-1">Scan type</label>
          <select className="bg-panel2 rounded-lg px-3 py-1.5 text-sm border border-white/10"
            value={scanType} onChange={(e) => setScanType(e.target.value)}>
            {SCAN_TYPES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </div>
        <div className="flex-1 min-w-40">
          <label className="text-xs text-slate-500 block mb-1">Target (CIDR / IP / localnet)</label>
          <input className="w-full bg-panel2 rounded-lg px-3 py-1.5 text-sm border border-white/10"
            value={target} onChange={(e) => setTarget(e.target.value)} />
        </div>
        <button className="btn" onClick={launch}>Launch scan</button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card p-0 overflow-hidden">
          <div className="p-3 font-semibold">Discovered Hosts</div>
          <table className="w-full">
            <thead className="bg-panel2"><tr>
              <th className="th">IP</th><th className="th">OS</th><th className="th">Ports</th><th className="th">Risk</th>
            </tr></thead>
            <tbody>
              {hostRows.map((h) => (
                <tr key={h.id} className="hover:bg-white/5">
                  <td className="td mono">{h.ip_address}</td>
                  <td className="td truncate max-w-[10rem]">{h.os_detected || "—"}</td>
                  <td className="td">{h.open_ports?.length || 0}</td>
                  <td className={`td font-bold ${riskColor(h.risk_score)}`}>{h.risk_score}</td>
                </tr>
              ))}
              {!hostRows.length && <tr><td className="td" colSpan={4}>No hosts yet — run a discovery scan.</td></tr>}
            </tbody>
          </table>
        </div>

        <div className="card p-0 overflow-hidden">
          <div className="p-3 font-semibold">Scan History</div>
          <table className="w-full">
            <thead className="bg-panel2"><tr>
              <th className="th">Type</th><th className="th">Target</th><th className="th">Status</th>
              <th className="th">Hosts</th><th className="th">Vulns</th>
            </tr></thead>
            <tbody>
              {scanRows.map((s) => (
                <tr key={s.id} className="hover:bg-white/5">
                  <td className="td">{s.scan_type}</td>
                  <td className="td mono">{s.target}</td>
                  <td className="td">{s.status}</td>
                  <td className="td">{s.host_count}</td>
                  <td className="td">{s.vulnerability_count}</td>
                </tr>
              ))}
              {!scanRows.length && <tr><td className="td" colSpan={5}>No scans run yet.</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
