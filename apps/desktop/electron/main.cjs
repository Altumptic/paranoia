// Paranoia desktop shell. The window is a sandboxed renderer; everything
// privileged (files, the native engine) goes through the narrow bridge in
// preload.cjs.

const { app, BrowserWindow, dialog, ipcMain, Menu, nativeTheme, shell, session } = require("electron");
const path = require("node:path");
const fs = require("node:fs");

const { EngineProcess } = require("./engine.cjs");
const { PythonRunner } = require("./python.cjs");

const isDev = !app.isPackaged && process.env.PARANOIA_DEV_URL;
const ROOT = path.resolve(__dirname, "..");

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
    titleBarOverlay: nativeTheme.shouldUseDarkColors ? { color: "#1f1e1d", symbolColor: "#c3c1b8", height: 47 } : { color: "#f5f4ee", symbolColor: "#4d4c48", height: 47 },
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

  // Never navigate away from the app or open new windows; http(s) links go to the browser.
  win.webContents.on("will-navigate", (e, url) => {
    if (!url.startsWith(isDev ? process.env.PARANOIA_DEV_URL : "file://")) e.preventDefault();
  });
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https:\/\//.test(url)) shell.openExternal(url);
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
  return isDev ? f.url.startsWith(process.env.PARANOIA_DEV_URL) : f.url.startsWith("file://");
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

handle("engine:request", async (_e, req) => {
  // Only forward the protocol's known operations.
  if (!req || !["open", "call", "close", "store", "ping", "export_patched", "load_pdb", "find_pdb", "debug"].includes(req.op)) throw new Error("invalid engine request");
  // Exports may only go to a path the user just picked in a save dialog.
  if (req.op === "export_patched" && req.path !== lastSavePath) throw new Error("export path was not chosen by the user");
  // Reads only from files the user chose.
  if (["open", "load_pdb", "find_pdb"].includes(req.op) && !(await pathAllowed(req.path))) throw new Error("this file was not opened by the user");
  // Starting a debuggee executes it: confirmed here, where the page cannot answer for the user.
  if (req.op === "debug" && req.method === "start") {
    const r = await dialog.showMessageBox(win, {
      type: "warning",
      title: "Run and debug",
      message: "Debugging runs this program on your computer.",
      detail: "Only debug files you trust, or do it inside a virtual machine. Malware will run with your user's permissions.",
      buttons: ["Cancel", "Run and debug"],
      defaultId: 0,
      cancelId: 0,
      noLink: true,
    });
    if (r.response !== 1) throw new Error("Debugging cancelled");
  }
  const res = await engine.request(req);
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

/** The most recent path the user confirmed in a save dialog; file writes are limited to it. */
let lastSavePath = null;

handle("dialog:save", async (_e, defaultName, filters) => {
  const r = await dialog.showSaveDialog(win, { defaultPath: String(defaultName ?? "export"), filters: Array.isArray(filters) ? filters : [] });
  lastSavePath = r.canceled ? null : r.filePath;
  return lastSavePath;
});

handle("file:write-text", async (_e, p, text) => {
  if (!p || p !== lastSavePath || typeof text !== "string") throw new Error("write path was not chosen by the user");
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
    win.setTitleBarOverlay({ color: c.color, symbolColor: c.symbolColor, height: 47 });
    win.setBackgroundColor(c.color);
  }
});

handle("app:reveal", (_e, p) => {
  if (typeof p === "string" && fs.existsSync(p)) shell.showItemInFolder(p);
});

// ---------------------------------------------------------------------------------------------
// Lifecycle

// No <webview>, no extra windows, no navigation for any web contents the app creates.
app.on("web-contents-created", (_e, contents) => {
  contents.on("will-attach-webview", (ev) => ev.preventDefault());
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
