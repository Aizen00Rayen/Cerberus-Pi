/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        // Phase 6.1 design system.
        ink: "#0a0f1e",
        panel: "#111a2e",
        panel2: "#16233d",
        cyan: { DEFAULT: "#00d4ff", dim: "#0892b3" },
        alert: "#ff4444",
        sev: {
          critical: "#ff2222",
          high: "#ff7700",
          medium: "#e0b000",
          low: "#3399ff",
          info: "#7a8699",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["'JetBrains Mono'", "ui-monospace", "monospace"],
      },
    },
  },
  plugins: [require("@tailwindcss/forms")],
};
