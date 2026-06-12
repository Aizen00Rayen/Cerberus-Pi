import { useState } from "react";
import { ChevronDown, ChevronRight, Check, X } from "lucide-react";
import ConfidenceBar from "./ConfidenceBar.jsx";

const TYPE_LABEL = { sqli: "SQLi", xss: "XSS", bruteforce: "Brute Force", dos: "DoS" };

export default function DetectionFeed({ rows, onVerdict }) {
  const [open, setOpen] = useState(null);
  return (
    <div className="card p-0 overflow-hidden">
      <div className="p-3 font-semibold flex items-center justify-between">
        <span>Live Detection Feed</span>
        <span className="text-xs text-slate-500">{rows.length} shown</span>
      </div>
      <table className="w-full">
        <thead className="bg-panel2">
          <tr>
            <th className="th w-6"></th><th className="th">Time</th><th className="th">Type</th>
            <th className="th">Confidence</th><th className="th">Src IP</th>
            <th className="th">Top Reason</th><th className="th">Verdict</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((d) => (
            <FeedRow key={d.id} d={d} open={open === d.id}
              onToggle={() => setOpen(open === d.id ? null : d.id)} onVerdict={onVerdict} />
          ))}
          {!rows.length && <tr><td className="td text-slate-600" colSpan={7}>No detections yet.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

function FeedRow({ d, open, onToggle, onVerdict }) {
  return (
    <>
      <tr className="hover:bg-white/5">
        <td className="td"><button onClick={onToggle} className="text-slate-500">
          {open ? <ChevronDown size={15} /> : <ChevronRight size={15} />}</button></td>
        <td className="td mono text-slate-400">{new Date(d.detected_at).toLocaleTimeString()}</td>
        <td className="td">{TYPE_LABEL[d.attack_type] || d.attack_type}</td>
        <td className="td"><ConfidenceBar value={d.confidence_score} /></td>
        <td className="td mono">{d.src_ip || "—"}</td>
        <td className="td truncate max-w-[16rem]">{d.features_triggered?.[0] || "—"}</td>
        <td className="td">
          {d.verdict === "pending" ? (
            <div className="flex gap-1">
              <button className="btn px-2 py-1" title="Confirm threat" onClick={() => onVerdict(d, "confirmed")}>
                <Check size={14} /></button>
              <button className="btn-danger px-2 py-1" title="False positive" onClick={() => onVerdict(d, "false_positive")}>
                <X size={14} /></button>
            </div>
          ) : (
            <span className={`badge ${d.verdict === "confirmed" ? "badge-HIGH" : "badge-INFO"}`}>
              {d.verdict === "confirmed" ? "confirmed" : "false +"}
            </span>
          )}
        </td>
      </tr>
      {open && (
        <tr className="bg-panel2/50">
          <td></td>
          <td className="td text-xs" colSpan={6}>
            <div className="space-y-2 py-1">
              <div>
                <span className="text-slate-500">Reasons: </span>
                <ul className="list-disc list-inside text-slate-300">
                  {(d.features_triggered || []).map((r, i) => <li key={i}>{r}</li>)}
                </ul>
              </div>
              <div>
                <span className="text-slate-500">Payload sample: </span>
                <code className="mono text-amber-300 break-all">{d.payload_sample || "—"}</code>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
