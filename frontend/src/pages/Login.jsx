import { useState } from "react";
import { Shield } from "lucide-react";
import { login, me } from "../api/client.js";

export default function Login({ onAuthed }) {
  const [username, setU] = useState("");
  const [password, setP] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setBusy(true); setErr("");
    try {
      await login(username, password);
      onAuthed(await me());
    } catch (e2) {
      setErr(e2?.response?.status === 429
        ? "Too many attempts. Try again later."
        : "Invalid credentials.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="h-screen grid place-items-center bg-ink">
      <form onSubmit={submit} className="card w-80 space-y-4">
        <div className="flex flex-col items-center gap-2">
          <Shield className="text-cyan" size={40} />
          <div className="font-bold tracking-widest">CERBERUS PI</div>
          <div className="text-[11px] text-slate-500">Secure admin access</div>
        </div>
        <input className="w-full bg-panel2 rounded-lg px-3 py-2 text-sm border border-white/10"
          placeholder="Username" value={username} onChange={(e) => setU(e.target.value)} autoFocus />
        <input type="password" className="w-full bg-panel2 rounded-lg px-3 py-2 text-sm border border-white/10"
          placeholder="Password" value={password} onChange={(e) => setP(e.target.value)} />
        {err && <div className="text-alert text-xs">{err}</div>}
        <button className="btn w-full justify-center" disabled={busy}>
          {busy ? "Authenticating…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
