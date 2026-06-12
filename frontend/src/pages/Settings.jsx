import { useQuery } from "@tanstack/react-query";
import { Cpu, MemoryStick, HardDrive, Thermometer } from "lucide-react";
import { api } from "../api/client.js";

export default function Settings() {
  const { data: health } = useQuery({
    queryKey: ["health"],
    queryFn: async () => (await api.get("/engine/status/health/")).data,
    refetchInterval: 5000,
  });
  const { data: engines } = useQuery({
    queryKey: ["engine-status"],
    queryFn: async () => (await api.get("/engine/status/")).data,
    refetchInterval: 5000,
  });

  async function control(engine, action) {
    await api.post("/engine/status/restart/", { engine, action });
  }

  const h = health || {};
  const eng = engines?.results || engines || [];

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold">Settings &amp; System Health</h1>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Metric icon={Cpu} label="CPU" value={h.cpu_percent != null ? `${h.cpu_percent}%` : "—"} />
        <Metric icon={MemoryStick} label="Memory" value={h.memory?.percent != null ? `${h.memory.percent}%` : "—"}
          sub={h.memory?.used_mb != null ? `${h.memory.used_mb}/${h.memory.total_mb} MB` : ""} />
        <Metric icon={HardDrive} label="Disk" value={h.disk?.percent != null ? `${h.disk.percent}%` : "—"}
          sub={h.disk?.free_gb != null ? `${h.disk.free_gb} GB free` : ""} />
        <Metric icon={Thermometer} label="Temp" value={h.temperature_c != null ? `${h.temperature_c}°C` : "—"} />
      </div>

      <div className="card">
        <h2 className="font-semibold mb-3">Engine Control</h2>
        <div className="space-y-3">
          {["suricata", "snort"].map((name) => {
            const e = eng.find((x) => x.engine_name === name) || {};
            const up = e.status === "running";
            return (
              <div key={name} className="flex items-center justify-between">
                <span className="flex items-center gap-2">
                  <span className={`w-2.5 h-2.5 rounded-full ${up ? "bg-green-400" : "bg-alert"}`} />
                  {name} <span className="text-xs text-slate-500">({e.status || "unknown"})</span>
                </span>
                <div className="flex gap-2">
                  <button className="btn" onClick={() => control(name, "start")}>Start</button>
                  <button className="btn" onClick={() => control(name, "restart")}>Restart</button>
                  <button className="btn-danger" onClick={() => control(name, "stop")}>Stop</button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <div className="card text-sm text-slate-500">
        <h2 className="font-semibold text-slate-200 mb-2">Appliance</h2>
        <p>Cerberus Pi is a single-admin appliance. Sessions expire after 30 minutes of
        inactivity. The monitored interface (eth0) is passive and does not respond to ping.
        Change the admin password from the Django admin or via <code className="mono">manage.py changepassword</code>.</p>
      </div>
    </div>
  );
}

function Metric({ icon: Icon, label, value, sub }) {
  return (
    <div className="stat">
      <Icon className="text-cyan" size={20} />
      <div className="text-2xl font-bold">{value}</div>
      <div className="text-xs text-slate-500">{label}{sub ? ` · ${sub}` : ""}</div>
    </div>
  );
}
