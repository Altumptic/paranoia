#!/usr/bin/env node
// Starts the PACKAGED desktop app for real, opens a file in it and checks what is on screen.
//
//   node scripts/smoke-app.mjs --dir apps/desktop/out/win-unpacked --file target/release/paranoia-engine.exe \
//        --version 0.10.0 [--shot smoke.png] [--no-sandbox] [--timeout 120]
//
// It drives the window over the Chrome DevTools protocol (the page itself has DevTools disabled,
// but the remote-debugging port is still served). Checks, in order:
//   - the window opens and the desktop bridge is there;
//   - the app's version is the package version and the engine is the one shipped in the package;
//   - the file given on the command line is analysed: three panels, a function list with entries;
//   - no uncaught exception or console error on the way.
// Then it asks the app to close (Browser.close) and waits for it to exit.
//
// Needs Node 22 (global WebSocket and fetch). On Linux run it under xvfb-run with --no-sandbox
// (CI runners cannot give chrome-sandbox the setuid bit).
import { spawn } from "node:child_process";
import { existsSync, readdirSync, statSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const args = process.argv.slice(2);
const opt = (name, fallback) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : fallback;
};
const flag = (name) => args.includes(name);
const dir = opt("--dir");
const sample = opt("--file");
const version = opt("--version");
const shot = opt("--shot");
const timeoutS = Number(opt("--timeout", "120"));
if (!dir || !sample || !version) {
  console.error("usage: smoke-app.mjs --dir UNPACKED_DIR --file SAMPLE --version X.Y.Z [--shot FILE] [--no-sandbox] [--timeout SECONDS]");
  process.exit(2);
}

/** The app's executable inside an electron-builder "unpacked" directory. */
function findApp(d) {
  if (process.platform === "win32") return join(d, "Paranoia.exe");
  if (process.platform === "darwin") {
    const macos = join(d, "Paranoia.app", "Contents", "MacOS");
    return join(macos, readdirSync(macos)[0]);
  }
  // Linux: the Electron binary is by far the largest file at the top of the folder.
  const files = readdirSync(d).map((n) => join(d, n)).filter((p) => statSync(p).isFile());
  return files.sort((a, b) => statSync(b).size - statSync(a).size)[0];
}

const exe = findApp(resolve(dir));
if (!existsSync(exe)) {
  console.error(`smoke: no app at ${exe}`);
  process.exit(2);
}
const port = 9300 + Math.floor(Math.random() * 500);
const profile = mkdtempSync(join(tmpdir(), "paranoia-smoke-"));
const problems = [];
const fail = (m) => problems.push(m);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const deadline = Date.now() + timeoutS * 1000;

const appArgs = [`--remote-debugging-port=${port}`, `--user-data-dir=${profile}`];
if (flag("--no-sandbox")) appArgs.push("--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage");
appArgs.push(resolve(sample));
console.log(`smoke: ${exe}`);
const child = spawn(exe, appArgs, { stdio: ["ignore", "pipe", "pipe"] });
let output = "";
child.stdout.on("data", (d) => (output += d));
child.stderr.on("data", (d) => (output += d));
let exited = null;
child.on("exit", (code, sig) => (exited = { code, sig }));

async function targets() {
  const r = await fetch(`http://127.0.0.1:${port}/json`);
  return r.json();
}

async function main() {
  let page;
  while (Date.now() < deadline) {
    if (exited) throw new Error(`the app exited before showing a window (code ${exited.code}, signal ${exited.sig})\n${output.slice(-2000)}`);
    try {
      page = (await targets()).find((t) => t.type === "page");
      if (page) break;
    } catch {
      /* not listening yet */
    }
    await sleep(500);
  }
  if (!page) throw new Error("no window appeared before the timeout");

  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((res, rej) => {
    ws.onopen = res;
    ws.onerror = () => rej(new Error("could not attach to the window"));
  });
  let id = 0;
  const pending = new Map();
  const logs = [];
  ws.onmessage = (m) => {
    const d = JSON.parse(m.data);
    if (d.id && pending.has(d.id)) {
      pending.get(d.id)(d);
      pending.delete(d.id);
    } else if (d.method === "Runtime.exceptionThrown") {
      logs.push(`exception: ${d.params.exceptionDetails.text} ${(d.params.exceptionDetails.exception?.description ?? "").slice(0, 300)}`);
    } else if (d.method === "Runtime.consoleAPICalled" && d.params.type === "error") {
      logs.push(`console.error: ${d.params.args.map((a) => a.value ?? a.description).join(" ").slice(0, 300)}`);
    }
  };
  const send = (method, params = {}) =>
    new Promise((res) => {
      const i = ++id;
      pending.set(i, res);
      ws.send(JSON.stringify({ id: i, method, params }));
    });
  const ev = async (expression) => {
    const r = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
    if (r.result?.exceptionDetails) throw new Error(`page script failed: ${r.result.exceptionDetails.text}`);
    return r.result?.result?.value;
  };
  await send("Runtime.enable");

  // The desktop bridge and the engine.
  const bridge = await ev(`!!window.paranoia && typeof window.paranoia.info === "function"`);
  if (!bridge) fail("the desktop bridge (window.paranoia) is missing");
  const info = await ev(`window.paranoia.info()`);
  console.log(`smoke: app ${info?.version}, Electron ${info?.electron}, ${info?.platform}`);
  if (info?.version !== version) fail(`the app says version ${info?.version}, the package is ${version}`);
  if (!/resources/i.test(String(info?.engine))) fail(`the engine is not the packaged one: ${info?.engine}`);

  // The file given on the command line is opened and analysed.
  const name = sample.split(/[\\/]/).pop();
  let state;
  while (Date.now() < deadline) {
    state = await ev(`(() => {
      const panels = [...document.querySelectorAll('[data-panel]')];
      const m = document.body.innerText.match(/FUNCTIONS\\s+(\\d[\\d\\s,.]*)/);
      return { panels: panels.length, hasFile: document.body.innerText.includes(${JSON.stringify(name)}), functions: m ? Number(m[1].replace(/\\D/g, "")) : 0 };
    })()`);
    if (state.panels >= 3 && state.hasFile && state.functions > 0) break;
    await sleep(1000);
  }
  console.log(`smoke: panels ${state?.panels}, file shown ${state?.hasFile}, functions ${state?.functions}`);
  if (!state || state.panels < 3) fail(`expected 3 panels, found ${state?.panels}`);
  if (!state?.hasFile) fail(`the window never showed ${name}`);
  if (!state || state.functions < 1) fail("the function list stayed empty");

  if (shot) {
    const s = await send("Page.captureScreenshot", { format: "png" });
    if (s.result?.data) writeFileSync(shot, Buffer.from(s.result.data, "base64"));
  }
  await sleep(500); // let late errors arrive
  for (const l of logs) fail(l);

  try {
    ws.close();
  } catch {
    /* already closed */
  }
  // Ask the whole browser to close; it never answers, because the connection goes away with it.
  const meta = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();
  const control = new WebSocket(meta.webSocketDebuggerUrl);
  await new Promise((res) => {
    control.onopen = () => {
      control.send(JSON.stringify({ id: 1, method: "Browser.close" }));
      res();
    };
    control.onerror = res;
  });
}

let code = 0;
try {
  await main();
} catch (e) {
  fail(String(e.message ?? e));
}
// The app should leave by itself after Browser.close; ours is the only process we end by force.
for (let i = 0; i < 20 && !exited; i++) await sleep(500);
if (!exited) {
  fail("the app did not exit after being asked to close");
  child.kill();
}
rmSync(profile, { recursive: true, force: true });
if (problems.length) {
  console.error("smoke: FAILED");
  for (const p of problems) console.error(`  - ${p}`);
  if (output.trim()) console.error(`--- app output (tail) ---\n${output.slice(-3000)}`);
  code = 1;
} else {
  console.log("smoke: ok");
}
process.exit(code);
