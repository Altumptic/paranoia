// Paranoia desktop shell. The window is a sandboxed renderer; everything
// privileged (files, the native engine) goes through the narrow bridge in
// preload.cjs.

const { app, BrowserWindow, dialog, ipcMain, Menu, nativeTheme, safeStorage, shell, session } = require("electron");
const path = require("node:path");
const fs = require("node:fs");

const { EngineProcess } = require("./engine.cjs");
const { PythonRunner } = require("./python.cjs");
const plugins = require("./plugins.cjs");
const ai = require("./ai.cjs");
const policy = require("./policy.cjs");

const isDev = !app.isPackaged && process.env.PARANOIA_DEV_URL;
const ROOT = path.resolve(__dirname, "..");
/** The packaged page. Only this exact file gets the bridge; other file:// pages do not. */
const APP_URL = policy.appUrl(path.join(ROOT, "dist", "index.html"));
const isOwnPage = (url) => (isDev ? typeof url === "string" && url.startsWith(process.env.PARANOIA_DEV_URL) : policy.isAppPage(url, APP_URL));

app.setAppUserModelId("app.paranoia.desktop");

// All local data lives in %APPDATA%\Paranoia (documented in docs/SECURITY-DESIGN.md).
// Builds before 0.5.1 used the npm package name; move that folder over once.
{
  const dataDir = path.join(app.getPath("appData"), "Paranoia");
  const legacy = path.join(app.getPath("appData"), "@paranoia", "desktop");
  if (!fs.existsSync(dataDir) && fs.existsSync(legacy)) {
    try {
      fs.renameSync(legacy, dataDir);
    } catch {
      /* keep going with a fresh folder */
    }
  }
  app.setPath("userData", dataDir);
}

/** The native engine binary: bundled in resources when packaged, the cargo build otherwise. */
function engineExe() {
  const name = process.platform === "win32" ? "paranoia-engine.exe" : "paranoia-engine";
  const candidates = app.isPackaged
    ? [path.join(process.resourcesPath, "engine", name)]
    : [
        path.join(ROOT, "..", "..", "target", "release", name),
        path.join(ROOT, "..", "..", "target", "debug", name),
        ...(process.env.CARGO_TARGET_DIR ? [path.join(process.env.CARGO_TARGET_DIR, "release", name)] : []),
      ];
  return candidates.find((p) => fs.existsSync(p)) ?? candidates[0];
}

/** @type {BrowserWindow | null} */
let win = null;
/** A path passed on the command line ("Open with Paranoia") before the window was ready. */
let pendingOpen = null;

const engine = new EngineProcess(engineExe(), ["--store", path.join(app.getPath("userData"), "workspace.redb")], (reason) => {
  win?.webContents.send("engine:restarted", reason);
});

const python = new PythonRunner(engine, (channel, payload) => win?.webContents.send(channel, payload), path.join(__dirname, "paranoia.py"));

function fileArg(argv) {
  // Skip the executable (and the app path in dev); accept the first existing file.
  return argv.slice(app.isPackaged ? 1 : 2).find((a) => !a.startsWith("-") && fs.existsSync(a) && fs.statSync(a).isFile()) ?? null;
}

function createWindow() {
  win = new BrowserWindow({
    width: 1480,
    height: 920,
    minWidth: 1000,
    minHeight: 640,
    show: false,
    backgroundColor: nativeTheme.shouldUseDarkColors ? "#1f1e1d" : "#f5f4ee",
    title: "Paranoia",
    icon: path.join(ROOT, "build", "icon.png"),
    titleBarStyle: "hidden",
    titleBarOverlay: nativeTheme.shouldUseDarkColors ? { color: "#1f1e1d", symbolColor: "#c3c1b8", height: 38 } : { color: "#f5f4ee", symbolColor: "#4d4c48", height: 38 },
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      spellcheck: false,
      devTools: !app.isPackaged,
    },
  });

  win.once("ready-to-show", () => {
    win.show();
    if (process.argv.includes("--maximized")) win.maximize();
  });

  // Never navigate away from the app's own page or open new windows. A few known https links
  // go to the system browser; anything else is dropped.
  win.webContents.on("will-navigate", (e, url) => {
    if (!isOwnPage(url)) e.preventDefault();
  });
  win.webContents.on("will-redirect", (e, url) => {
    if (!isOwnPage(url)) e.preventDefault();
  });
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (policy.externalAllowed(url)) shell.openExternal(url);
    return { action: "deny" };
  });

  if (isDev) win.loadURL(process.env.PARANOIA_DEV_URL);
  else win.loadFile(path.join(ROOT, "dist", "index.html"));

  win.webContents.on("did-finish-load", () => {
    if (pendingOpen) {
      win.webContents.send("app:open-path", pendingOpen);
      pendingOpen = null;
    }
  });
  win.on("closed", () => (win = null));
}

// ---------------------------------------------------------------------------------------------
// IPC
//
// Every handler checks that the request comes from the app's own top-level page, and the
// operations that touch the file system or run code are limited to what the user chose in
// a native dialog (open / save / confirm). A compromised renderer cannot widen that.

/** @param {Electron.IpcMainInvokeEvent | Electron.IpcMainEvent} e */
function trusted(e) {
  const f = e.senderFrame;
  if (!win || !f || e.sender !== win.webContents || f !== win.webContents.mainFrame) return false;
  return isOwnPage(f.url);
}

/** ipcMain.handle with the sender check. */
function handle(channel, fn) {
  ipcMain.handle(channel, (e, ...args) => {
    if (!trusted(e)) throw new Error("request from an untrusted frame");
    return fn(e, ...args);
  });
}

/** Files the user chose (dialogs, command line, drag & drop, recent list): the only ones the engine may open. */
const allowedPaths = new Set();
const normPath = (p) => {
  const r = path.resolve(String(p));
  return process.platform === "win32" ? r.toLowerCase() : r;
};
function allowPath(p) {
  if (typeof p === "string" && p) allowedPaths.add(normPath(p));
}
async function pathAllowed(p) {
  if (typeof p !== "string" || !p) return false;
  if (allowedPaths.has(normPath(p))) return true;
  // Entries of the recent-files list were opened by the user before.
  try {
    const recent = await engine.request({ op: "store", method: "recent_list", args: null });
    if (Array.isArray(recent) && recent.some((r) => r && typeof r.path === "string" && normPath(r.path) === normPath(p))) {
      allowPath(p);
      return true;
    }
  } catch {
    /* no store: fall through */
  }
  return false;
}

/** Python runs with the user's permissions: confirmed once per session in a native dialog. */
let pythonConfirmed = false;

/** Engine session handle → the file it was opened from, for the debugger confirmation. */
const sessionPaths = new Map();

/** Takes the path picked in the last save dialog. Each pick allows one write. */
function takeSavePath(p) {
  if (!p || p !== lastSavePath) return false;
  lastSavePath = null;
  writtenPaths.add(normPath(p));
  return true;
}

handle("engine:request", async (_e, req) => {
  // Only forward the protocol's known operations.
  if (!req || !["open", "call", "close", "store", "ping", "export_patched", "load_pdb", "find_pdb", "debug", "diff", "memory"].includes(req.op)) throw new Error("invalid engine request");
  // The function knowledge base: no paths, a fixed set of methods.
  if (req.op === "memory" && !policy.memoryMethodAllowed(req.method)) throw new Error("invalid memory request");
  // Exports may only go to a path the user just picked in a save dialog.
  if (req.op === "export_patched" && !takeSavePath(req.path)) throw new Error("export path was not chosen by the user");
  // Reads only from files the user chose.
  if (["open", "load_pdb", "find_pdb"].includes(req.op) && !(await pathAllowed(req.path))) throw new Error("this file was not opened by the user");
  // The store is also where the recent-files allow-list lives: the page gets a fixed set of
  // methods and may only add files it really opened.
  if (req.op === "store") {
    if (!policy.storeMethodAllowed(req.method)) throw new Error("invalid store request");
    if (req.method === "recent_add" && !policy.recentAddAllowed(req.args, (p) => allowedPaths.has(normPath(p)))) throw new Error("this file was not opened by the user");
  }
  // Starting a debuggee executes it: confirmed here, where the page cannot answer for the user.
  // The dialog names the program and the arguments, which come from the page.
  if (req.op === "debug" && req.method === "start") {
    const r = await dialog.showMessageBox(win, {
      type: "warning",
      title: "Run and debug",
      message: "Debugging runs this program on your computer.",
      detail: policy.debugDetail(sessionPaths.get(req.handle), req.args?.cmdline),
      buttons: ["Cancel", "Run and debug"],
      defaultId: 0,
      cancelId: 0,
      noLink: true,
    });
    if (r.response !== 1) throw new Error("Debugging cancelled");
  }
  const res = await engine.request(req);
  if (req.op === "open" && Number.isInteger(res)) sessionPaths.set(res, req.path);
  if (req.op === "close") sessionPaths.delete(req.handle);
  if (req.op === "find_pdb" && typeof res === "string") allowPath(res);
  return res;
});

// Python scripts run in the user's own interpreter; they can only call the engine for the open session.
handle("python:status", () => python.status());
handle("python:run", async (_e, code, session, cursor) => {
  if (typeof code !== "string" || !Number.isInteger(session)) throw new Error("invalid script request");
  if (!pythonConfirmed) {
    const st = python.status();
    const r = await dialog.showMessageBox(win, {
      type: "question",
      title: "Run Python script",
      message: "Run this script with your Python interpreter?",
      detail: `Python scripts are ordinary programs: they run with your user's permissions and can read files and use the network. Paranoia asks once per session.\n\nInterpreter: ${st.exe ?? "not found"}`,
      buttons: ["Cancel", "Run"],
      defaultId: 1,
      cancelId: 0,
      noLink: true,
    });
    if (r.response !== 1) throw new Error("Script cancelled");
    pythonConfirmed = true;
  }
  return python.run(code, session, Number(cursor) || 0);
});
handle("python:stop", () => python.stop());

// AI assistant: off until configured. The page never sees the key and has no network access;
// this process makes the request, and a remote (non-loopback) host needs the user's explicit consent.
const aiFile = () => path.join(app.getPath("userData"), "ai-settings.json");
/** The API key kept in memory when the OS cannot encrypt it for storage. */
let aiSessionKey = null;
let aiRemoteConfirmed = null;
let aiCancel = null;
function aiRead() {
  try {
    const j = JSON.parse(fs.readFileSync(aiFile(), "utf8"));
    return j && typeof j === "object" ? j : {};
  } catch {
    return {};
  }
}
const aiWrite = (s) => fs.writeFileSync(aiFile(), JSON.stringify(s), "utf8");
function aiKey(s) {
  if (aiSessionKey) return aiSessionKey;
  if (!s.keyEnc || !safeStorage.isEncryptionAvailable()) return "";
  try {
    return safeStorage.decryptString(Buffer.from(s.keyEnc, "base64"));
  } catch {
    return "";
  }
}
const aiPublic = (s) => ({ ...ai.publicSettings({ ...s, keyEnc: s.keyEnc || (aiSessionKey ? "session" : "") }), encryption: safeStorage.isEncryptionAvailable() });

// The assistant's disclosure ledger: one hash-chained JSON line per request and per answer, in
// the app's data folder. It records hashes, counts and the host — never the code or the answer.
const aiLedgerFile = () => path.join(app.getPath("userData"), "assistant-ledger.jsonl");
/** Appends one ledger line and syncs it to disk; throws when the ledger cannot be written. */
function aiLedgerAppend(entry) {
  const file = aiLedgerFile();
  let prev = null;
  try {
    const text = fs.readFileSync(file, "utf8");
    const last = text.split("\n").filter((l) => l.trim()).pop();
    if (last) prev = ai.sha256Hex(last);
  } catch (e) {
    if (e?.code !== "ENOENT") throw e;
  }
  const line = ai.ledgerLine(prev, entry);
  const fd = fs.openSync(file, "a");
  try {
    fs.writeSync(fd, `${line}\n`);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

handle("ai:get", () => aiPublic(aiRead()));
handle("ai:set", async (_e, input) => {
  if (!input || typeof input !== "object") throw new Error("invalid settings");
  const cur = aiRead();
  const next = { model: String(input.model ?? "").trim().slice(0, 120) };
  // Privacy options live with the other AI settings; redaction is opt-in.
  next.redactStrings = input.redactStrings === undefined ? cur.redactStrings === true : input.redactStrings === true;
  next.redactIps = input.redactIps === undefined ? cur.redactIps === true : input.redactIps === true;
  const raw = String(input.endpoint ?? "").trim();
  if (raw) {
    const ep = ai.parseEndpoint(raw);
    next.endpoint = ep.url;
    if (ep.local && ep.url !== cur.endpoint) {
      const r = await dialog.showMessageBox(win, {
        type: "question",
        title: "AI assistant",
        message: `Use the model server at ${ep.url}?`,
        detail: "This address is on this computer. The assistant sends it the decompiled text of a function only when you choose an Assistant command.",
        buttons: ["Cancel", "Use it"],
        defaultId: 1,
        cancelId: 0,
        noLink: true,
      });
      if (r.response !== 1) throw new Error("Endpoint not changed");
    }
    if (!ep.local && cur.approvedHost !== ep.host) {
      const r = await dialog.showMessageBox(win, {
        type: "warning",
        title: "Use a remote AI service",
        message: `Send function code to ${ep.host}?`,
        detail:
          `The assistant sends the decompiled text of the function you ask about (up to ${ai.MAX_CODE_CHARS} characters per request) to ${ep.host}. ` +
          `That service may log it. Nothing is sent until you choose an assistant command, and nothing else from the file is sent.\n\n` +
          `${ai.redactionSummary(next.redactStrings, next.redactIps)}\n\nFor a binary you must keep private, use a local model (Ollama, LM Studio) instead.`,
        buttons: ["Cancel", "Allow this host"],
        defaultId: 0,
        cancelId: 0,
        noLink: true,
      });
      if (r.response !== 1) throw new Error("Remote endpoint not allowed");
      next.approvedHost = ep.host;
    } else if (!ep.local) {
      next.approvedHost = cur.approvedHost;
    }
  }
  // Key: undefined keeps it, null / "" clears it, a string replaces it (encrypted with the OS keystore when possible).
  if (input.key === undefined) {
    if (cur.keyEnc) next.keyEnc = cur.keyEnc;
  } else if (typeof input.key === "string" && input.key) {
    if (safeStorage.isEncryptionAvailable()) {
      next.keyEnc = safeStorage.encryptString(input.key).toString("base64");
      aiSessionKey = null;
    } else {
      aiSessionKey = input.key; // memory only; never written in clear text
    }
  } else {
    aiSessionKey = null;
  }
  aiRemoteConfirmed = null;
  aiWrite(next);
  return aiPublic(next);
});
handle("ai:cancel", () => aiCancel?.abort());

/** The saved endpoint, refused if it is remote and its host was not approved when it was saved. */
function aiApprovedEndpoint() {
  const s = aiRead();
  if (!s.endpoint) throw new Error("Set an endpoint first");
  const ep = ai.parseEndpoint(s.endpoint);
  if (!ep.local && s.approvedHost !== ep.host) throw new Error(`Save the settings and allow ${ep.host} first`);
  return { s, ep };
}

// The models a server offers. Sends only the API key.
handle("ai:models", async () => {
  const { s } = aiApprovedEndpoint();
  return ai.listModels({ endpoint: s.endpoint, key: aiKey(s) });
});

// A fixed one-line prompt that proves endpoint, key and model work. Sends no code.
handle("ai:test", async () => {
  const { s, ep } = aiApprovedEndpoint();
  const started = Date.now();
  const text = await ai.chat({ endpoint: s.endpoint, key: aiKey(s), model: s.model, messages: ai.TEST_MESSAGES });
  return { text: text.slice(0, 300), millis: Date.now() - started, host: ep.host, local: ep.local };
});
// One assistant request. Redaction (opt-in) replaces the file's strings and IP-like constants
// before anything leaves; the request and the answer are recorded in the disclosure ledger, and
// a request whose record cannot be written is not sent (the same rule as `paranoia mcp`).
handle("ai:ask", async (_e, req) => {
  if (!req || typeof req !== "object" || typeof req.task !== "string" || typeof req.code !== "string") throw new Error("invalid assistant request");
  if (req.code.length > 400000) throw new Error("The function is too large to send");
  const s = aiRead();
  if (!s.endpoint) throw new Error("The assistant is off — choose Assistant → Settings… and point it at a model server");
  if (!String(s.model ?? "").trim()) throw new Error("No model is chosen — pick one in Assistant → Settings");
  const ep = ai.parseEndpoint(s.endpoint);
  // The page sends the options it has saved; the main process keeps the last word.
  const redactStrings = req.redactStrings === true || s.redactStrings === true;
  const redactIps = req.redactIps === true || s.redactIps === true;
  const strings = Array.isArray(req.strings) ? req.strings.filter((v) => typeof v === "string") : [];
  const redactor = ai.createRedactor({ strings, redactStrings, redactIps });
  const redactions = { strings: 0, ips: 0 };
  const messages = ai.buildMessages(req.task, req).map((m) => {
    const r = redactor.apply(m.content);
    redactions.strings += r.strings;
    redactions.ips += r.ips;
    return { ...m, content: r.text };
  });
  if (!ep.local && aiRemoteConfirmed !== ep.host) {
    const r = await dialog.showMessageBox(win, {
      type: "question",
      title: ai.TASKS[req.task].title,
      message: `Send this function to ${ep.host}?`,
      detail:
        `${Math.min(req.code.length, ai.MAX_CODE_CHARS)} characters of decompiled code for “${String(req.name ?? "").slice(0, 80)}” will leave this computer. ` +
        `${ai.redactionSummary(redactStrings, redactIps)}\n\nParanoia asks once per session for each host.`,
      buttons: ["Cancel", "Send"],
      defaultId: 0,
      cancelId: 0,
      noLink: true,
    });
    if (r.response !== 1) throw new Error("Cancelled");
    aiRemoteConfirmed = ep.host;
  }
  // Record the request before sending it: nothing leaves unrecorded.
  try {
    aiLedgerAppend({
      event: "request",
      host: ep.host,
      local: ep.local,
      task: req.task,
      model: String(s.model ?? ""),
      redact_strings: redactStrings,
      redact_ips: redactIps,
      redactions,
      request_sha256: ai.sha256Hex(JSON.stringify(messages)),
    });
  } catch (e) {
    throw new Error(`The disclosure ledger ${aiLedgerFile()} could not be written (${e instanceof Error ? e.message : e}); nothing was sent.`);
  }
  aiCancel?.abort();
  const ctl = new AbortController();
  aiCancel = ctl;
  try {
    const text = await ai.chat({ endpoint: s.endpoint, key: aiKey(s), model: s.model, messages, signal: ctl.signal });
    try {
      aiLedgerAppend({
        event: "answer",
        host: ep.host,
        task: req.task,
        response_sha256: ai.sha256Hex(text),
        response_chars: text.length,
      });
    } catch (e) {
      throw new Error(`The answer was withheld: the disclosure ledger ${aiLedgerFile()} could not be written (${e instanceof Error ? e.message : e}).`);
    }
    return { text, name: req.task === "name" ? ai.parseName(text) : null, host: ep.host, local: ep.local, redactions };
  } finally {
    if (aiCancel === ctl) aiCancel = null;
  }
});

// Plugins: folders under %APPDATA%\Paranoia\plugins. The renderer only learns names and commands;
// the script text is read fresh from disk here, after the user has agreed to run exactly that version.
const pluginsDir = () => path.join(app.getPath("userData"), "plugins");
const pluginTrustFile = () => path.join(app.getPath("userData"), "plugins-trust.json");
handle("plugins:list", () => {
  fs.mkdirSync(pluginsDir(), { recursive: true });
  const r = plugins.scan(pluginsDir());
  const trusted = plugins.readTrust(pluginTrustFile());
  return { dir: pluginsDir(), plugins: r.plugins.map((p) => ({ ...p, trusted: trusted.has(p.hash) })), errors: r.errors };
});
handle("plugins:folder", async () => {
  fs.mkdirSync(pluginsDir(), { recursive: true });
  await shell.openPath(pluginsDir());
});
handle("plugins:run", async (_e, id, commandId) => {
  if (typeof id !== "string" || typeof commandId !== "string") throw new Error("invalid plugin request");
  const { plugin, code, hash } = plugins.load(pluginsDir(), id);
  const script = plugins.invocation(plugin, commandId, code);
  const trust = plugins.readTrust(pluginTrustFile());
  if (!trust.has(hash)) {
    const r = await dialog.showMessageBox(win, {
      type: "question",
      title: "Run plugin",
      message: `Run “${plugin.name}” ${plugin.version}?`,
      detail:
        `A plugin is a script written by someone else. ` +
        (plugin.language === "py"
          ? "This one is Python: it runs with your user's permissions and can read files and use the network.\n\n"
          : "This one is JavaScript: it can read and change this analysis through the pn API, but cannot touch your files or the network.\n\n") +
        `Folder: ${path.join(pluginsDir(), id)}\nScript: ${plugin.entry} (${code.length} bytes)\nFingerprint: ${hash.slice(0, 16)}…\n\nChanging the plugin asks again.`,
      buttons: ["Cancel", "Run once", "Always run this version"],
      defaultId: 0,
      cancelId: 0,
      noLink: true,
    });
    if (r.response === 0) throw new Error("Plugin cancelled");
    if (r.response === 2) {
      trust.add(hash);
      plugins.writeTrust(pluginTrustFile(), trust);
    }
  }
  return { language: plugin.language, name: plugin.name, code: script };
});

handle("dialog:open", async () => {
  const r = await dialog.showOpenDialog(win, {
    title: "Open binary",
    properties: ["openFile"],
    filters: [
      { name: "Executables & libraries", extensions: ["exe", "dll", "sys", "ocx", "efi", "so", "o", "ko", "dylib", "bundle", "elf", "bin", "out"] },
      { name: "All files", extensions: ["*"] },
    ],
  });
  if (r.canceled) return null;
  allowPath(r.filePaths[0]);
  return r.filePaths[0];
});

/** The most recent path the user confirmed in a save dialog; it allows exactly one write. */
let lastSavePath = null;
/** Files written after a save dialog, which the page may later show in the file manager. */
const writtenPaths = new Set();

handle("dialog:save", async (_e, defaultName, filters) => {
  const r = await dialog.showSaveDialog(win, { defaultPath: String(defaultName ?? "export"), filters: Array.isArray(filters) ? filters : [] });
  lastSavePath = r.canceled ? null : r.filePath;
  return lastSavePath;
});

handle("file:write-text", async (_e, p, text) => {
  if (typeof text !== "string" || !takeSavePath(p)) throw new Error("write path was not chosen by the user");
  await fs.promises.writeFile(p, text, "utf8");
});

handle("dialog:pdb", async () => {
  const r = await dialog.showOpenDialog(win, { title: "Load PDB symbols", properties: ["openFile"], filters: [{ name: "Program database", extensions: ["pdb"] }] });
  if (r.canceled) return null;
  allowPath(r.filePaths[0]);
  return r.filePaths[0];
});

handle("app:info", () => ({ version: app.getVersion(), engine: engineExe(), electron: process.versions.electron, platform: process.platform }));

// Drag & drop: the preload resolves a dropped File to its path (only real files have one).
ipcMain.on("path:allow", (e, p) => {
  if (trusted(e)) allowPath(p);
});

ipcMain.on("app:titlebar", (e, c) => {
  if (!trusted(e)) return;
  const hex = /^#[0-9a-f]{6}$/i;
  if (win && c && hex.test(c.color) && hex.test(c.symbolColor)) {
    // Missing on macOS: calling it there throws out of this handler and Electron shows an
    // "A JavaScript error occurred in the main process" dialog on every theme change.
    if (policy.titleBarOverlaySupported(process.platform)) win.setTitleBarOverlay({ color: c.color, symbolColor: c.symbolColor, height: 38 });
    win.setBackgroundColor(c.color);
  }
});

// Show a file in the file manager: only files the user opened or saved.
handle("app:reveal", (_e, p) => {
  if (typeof p !== "string" || !(allowedPaths.has(normPath(p)) || writtenPaths.has(normPath(p)))) return;
  if (fs.existsSync(p)) shell.showItemInFolder(p);
});

// ---------------------------------------------------------------------------------------------
// Lifecycle

// No <webview>, no extra windows, no navigation for any web contents the app creates.
app.on("web-contents-created", (_e, contents) => {
  contents.on("will-attach-webview", (ev) => ev.preventDefault());
  contents.on("will-navigate", (ev, url) => {
    if (!isOwnPage(url)) ev.preventDefault();
  });
  contents.setWindowOpenHandler(() => ({ action: "deny" }));
});

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on("second-instance", (_e, argv) => {
    const f = fileArg(argv);
    allowPath(f);
    if (win) {
      if (win.isMinimized()) win.restore();
      win.focus();
      if (f) win.webContents.send("app:open-path", f);
    }
  });

  app.whenReady().then(() => {
    // A strict CSP for the packaged page: no remote code, no remote connections, no eval
    // (console scripts run in a dedicated worker). index.html carries the same policy.
    if (!isDev) {
      session.defaultSession.webRequest.onHeadersReceived((details, cb) => {
        if (details.resourceType !== "mainFrame") return cb({});
        cb({
          responseHeaders: {
            ...details.responseHeaders,
            "Content-Security-Policy": ["default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; object-src 'none'; frame-ancestors 'none'"],
          },
        });
      });
    }
    // No camera, microphone, notifications, geolocation, …: the app needs none.
    session.defaultSession.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));
    session.defaultSession.setPermissionCheckHandler(() => false);

    Menu.setApplicationMenu(null);
    pendingOpen = fileArg(process.argv);
    allowPath(pendingOpen);
    engine.start();
    createWindow();
  });

  app.on("window-all-closed", () => {
    python.stop();
    engine.stop();
    app.quit();
  });
}
