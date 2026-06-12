// Axios client + CSRF bootstrap + WebSocket helper (Phase 6.3).
import axios from "axios";

export const api = axios.create({
  baseURL: "/api",
  withCredentials: true,
  xsrfCookieName: "csrftoken",
  xsrfHeaderName: "X-CSRFToken",
});

// Fetch a CSRF cookie/token before any unsafe request (login etc.).
export async function bootstrapCsrf() {
  const { data } = await api.get("/auth/csrf/");
  api.defaults.headers.common["X-CSRFToken"] = data.csrfToken;
  return data.csrfToken;
}

export async function login(username, password) {
  await bootstrapCsrf();
  const { data } = await api.post("/auth/login/", { username, password });
  return data;
}

export async function logout() {
  await api.post("/auth/logout/");
}

export async function me() {
  const { data } = await api.get("/auth/me/");
  return data;
}

// --- WebSocket helper -------------------------------------------------------
// Opens a same-origin secure WS and reconnects with backoff.
export function openSocket(path, onMessage) {
  let ws;
  let closed = false;
  let backoff = 1000;

  function connect() {
    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    ws = new WebSocket(`${proto}://${window.location.host}${path}`);
    ws.onmessage = (e) => {
      try {
        onMessage(JSON.parse(e.data));
      } catch {
        /* ignore malformed frame */
      }
    };
    ws.onopen = () => { backoff = 1000; };
    ws.onclose = () => {
      if (closed) return;
      setTimeout(connect, backoff);
      backoff = Math.min(backoff * 2, 15000);
    };
  }
  connect();
  return () => { closed = true; ws && ws.close(); };
}
