import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Production pages carry their Content-Security-Policy in a <meta> tag as well, so it holds
// wherever the build is served from. Console scripts run in a worker, so no 'unsafe-eval'.
const CSP = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; object-src 'none'";

// `base: "./"` lets the desktop shell load the build from file://.
export default defineConfig({
  plugins: [
    react(),
    {
      name: "csp",
      apply: "build",
      transformIndexHtml: (html) => html.replace("<head>", `<head>\n    <meta http-equiv="Content-Security-Policy" content="${CSP}" />`),
    },
  ],
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
