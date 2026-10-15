import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `base: "./"` lets the desktop shell load the build from file://.
export default defineConfig({
  plugins: [react()],
  base: "./",
  clearScreen: false,
  server: { port: 1420, strictPort: true, watch: { ignored: ["**/release/**", "**/dist/**"] } },
  worker: { format: "es" },
  build: {
    target: "es2022",
    sourcemap: false,
    chunkSizeWarningLimit: 1500,
  },
});
