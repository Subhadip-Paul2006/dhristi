/// <reference types="vitest/config" />
import path from "node:path";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// In Docker the server host differs; locally the FastAPI dev server is :8000.
const apiTarget = process.env.VITE_API_PROXY ?? "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  build: {
    // The app half (React Flow + Recharts) is a single lazy chunk behind
    // /app/*; landing visitors never download it. NOTE: manualChunks was
    // tried and reverted — rollup hoists small shared helpers into the
    // vendor chunks, which makes the ENTRY import them eagerly and defeats
    // the split. Default chunking hoists shared deps up into the entry.
    chunkSizeWarningLimit: 700,
  },
  server: {
    host: true,
    port: 5173,
    proxy: {
      "/api": { target: apiTarget, changeOrigin: true },
      "/health": { target: apiTarget, changeOrigin: true },
    },
  },
  // `vite preview` (used by the Docker web image) needs its own proxy — the
  // `server` block above only applies to `vite dev`.
  preview: {
    host: true,
    port: 5173,
    allowedHosts: true,
    proxy: {
      "/api": { target: apiTarget, changeOrigin: true },
      "/health": { target: apiTarget, changeOrigin: true },
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test-setup.ts"],
  },
});
