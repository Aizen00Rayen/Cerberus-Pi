import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev server proxies API + WS to the local Daphne (via Nginx in prod).
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": { target: "https://localhost", changeOrigin: true, secure: false },
      "/ws": { target: "wss://localhost", ws: true, secure: false },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
  },
});
