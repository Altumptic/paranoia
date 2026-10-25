// The only surface the renderer gets: a handful of explicit functions.

const { contextBridge, ipcRenderer, webUtils } = require("electron");

contextBridge.exposeInMainWorld("paranoia", {
  engine: (req) => ipcRenderer.invoke("engine:request", req),
  openDialog: () => ipcRenderer.invoke("dialog:open"),
  pdbDialog: () => ipcRenderer.invoke("dialog:pdb"),
  info: () => ipcRenderer.invoke("app:info"),
  reveal: (p) => ipcRenderer.invoke("app:reveal", p),
  saveDialog: (name, filters) => ipcRenderer.invoke("dialog:save", name, filters),
  writeText: (p, text) => ipcRenderer.invoke("file:write-text", p, text),
  setTitleBar: (color, symbolColor) => ipcRenderer.send("app:titlebar", { color, symbolColor }),
  pathForFile: (file) => {
    try {
      return webUtils.getPathForFile(file) || null;
    } catch {
      return null;
    }
  },
  onOpenPath: (cb) => {
    const h = (_e, p) => cb(p);
    ipcRenderer.on("app:open-path", h);
    return () => ipcRenderer.removeListener("app:open-path", h);
  },
  python: {
    status: () => ipcRenderer.invoke("python:status"),
    run: (code, handle, cursor) => ipcRenderer.invoke("python:run", code, handle, cursor),
    stop: () => ipcRenderer.invoke("python:stop"),
    /** Output, exit, goto and refresh events from the running script. */
    on: (cb) => {
      const channels = ["python:output", "python:exit", "python:goto", "python:refresh"];
      const hs = channels.map((ch) => {
        const h = (_e, p) => cb(ch.slice(7), p);
        ipcRenderer.on(ch, h);
        return [ch, h];
      });
      return () => hs.forEach(([ch, h]) => ipcRenderer.removeListener(ch, h));
    },
  },
  onEngineRestarted: (cb) => {
    const h = (_e, r) => cb(r);
    ipcRenderer.on("engine:restarted", h);
    return () => ipcRenderer.removeListener("engine:restarted", h);
  },
});
