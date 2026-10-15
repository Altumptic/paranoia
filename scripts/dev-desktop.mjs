// Desktop dev loop: Vite dev server with HMR + Electron pointed at it.
// Requires a built engine: `cargo build --release -p paranoia-engine`.
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const app = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../apps/desktop");
const require = createRequire(path.join(app, "package.json"));
const url = "http://localhost:1420";

const vite = spawn(process.execPath, [require.resolve("vite/bin/vite.js")], { cwd: app, stdio: "inherit" });
const wait = async () => {
  for (let i = 0; i < 100; i++) {
    try {
      if ((await fetch(url)).ok) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error("vite did not start");
};
await wait();
const electron = spawn(require("electron"), ["."], { cwd: app, stdio: "inherit", env: { ...process.env, PARANOIA_DEV_URL: url } });
electron.on("exit", (code) => {
  vite.kill();
  process.exit(code ?? 0);
});
