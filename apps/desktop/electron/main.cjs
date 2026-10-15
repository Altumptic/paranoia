// Paranoia desktop shell. The window is a sandboxed renderer; everything
// privileged (files, the native engine) goes through the narrow bridge in
// preload.cjs.

const { app, BrowserWindow, dialog, ipcMain, Menu, nativeTheme, shell, session } = require("electron");
const path = require("node:path");
const fs = require("node:fs");

const { EngineProcess } = require("./engine.cjs");

const isDev = !app.isPackaged && process.env.PARANOIA_DEV_URL;
const ROOT = path.resolve(__dirname, "..");

app.setAppUserModelId("app.paranoia.desktop");

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
      devTools: !app.isPackaged || process.argv.includes("--devtools"),
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

ipcMain.handle("engine:request", (_e, req) => {
  // Only forward the protocol's known operations.
  if (!req || !["open", "call", "close", "store", "ping"].includes(req.op)) throw new Error("invalid engine request");
  return engine.request(req);
});

ipcMain.handle("dialog:open", async () => {
  const r = await dialog.showOpenDialog(win, {
    title: "Open binary",
    properties: ["openFile"],
    filters: [
      { name: "Executables & libraries", extensions: ["exe", "dll", "sys", "ocx", "efi", "so", "o", "ko", "dylib", "bundle", "elf", "bin", "out"] },
      { name: "All files", extensions: ["*"] },
    ],
  });
  return r.canceled ? null : r.filePaths[0];
});

ipcMain.handle("app:info", () => ({ version: app.getVersion(), engine: engineExe(), electron: process.versions.electron, platform: process.platform }));

ipcMain.on("app:titlebar", (_e, c) => {
  const hex = /^#[0-9a-f]{6}$/i;
  if (win && c && hex.test(c.color) && hex.test(c.symbolColor)) {
    win.setTitleBarOverlay({ color: c.color, symbolColor: c.symbolColor, height: 47 });
    win.setBackgroundColor(c.color);
  }
});

ipcMain.handle("app:reveal", (_e, p) => {
  if (typeof p === "string" && fs.existsSync(p)) shell.showItemInFolder(p);
});

// ---------------------------------------------------------------------------------------------
// Lifecycle

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on("second-instance", (_e, argv) => {
    const f = fileArg(argv);
    if (win) {
      if (win.isMinimized()) win.restore();
      win.focus();
      if (f) win.webContents.send("app:open-path", f);
    }
  });

  app.whenReady().then(() => {
    // A strict CSP for the packaged renderer: no remote code, no remote connections.
    if (!isDev) {
      session.defaultSession.webRequest.onHeadersReceived((details, cb) => {
        cb({
          responseHeaders: {
            ...details.responseHeaders,
            "Content-Security-Policy": [
              "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self' blob:; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'",
            ],
          },
        });
      });
    }
    session.defaultSession.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));

    Menu.setApplicationMenu(null);
    pendingOpen = fileArg(process.argv);
    engine.start();
    createWindow();
  });

  app.on("window-all-closed", () => {
    engine.stop();
    app.quit();
  });
}
