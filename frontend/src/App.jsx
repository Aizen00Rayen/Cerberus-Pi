import { useEffect, useState } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import { me } from "./api/client.js";
import Layout from "./components/Layout.jsx";
import Login from "./pages/Login.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import Threats from "./pages/Threats.jsx";
import Scanner from "./pages/Scanner.jsx";
import LogVault from "./pages/LogVault.jsx";
import Reports from "./pages/Reports.jsx";
import Settings from "./pages/Settings.jsx";
import IntelligencePage from "./pages/IntelligencePage.jsx"; // Phase 11

export default function App() {
  const [auth, setAuth] = useState(null); // null=loading, false=anon, {}=user

  useEffect(() => {
    me().then(setAuth).catch(() => setAuth(false));
  }, []);

  if (auth === null) {
    return <div className="h-screen grid place-items-center text-cyan">Loading Cerberus…</div>;
  }
  if (!auth) {
    return <Login onAuthed={setAuth} />;
  }

  return (
    <Layout user={auth} onLogout={() => setAuth(false)}>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/threats" element={<Threats />} />
        <Route path="/scanner" element={<Scanner />} />
        <Route path="/intelligence" element={<IntelligencePage />} />
        <Route path="/logs" element={<LogVault />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  );
}
