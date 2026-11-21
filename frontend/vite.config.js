import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In dev, /api/* is forwarded to the proxy backend so no CORS setup is needed.
const target = process.env.VITE_PROXY_TARGET || "http://localhost:8000";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target,
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
});
