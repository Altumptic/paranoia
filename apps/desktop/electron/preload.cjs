// The only surface the renderer gets: a handful of explicit functions.

const { contextBridge, ipcRenderer, webUtils } = require("electron");

contextBridge.exposeInMainWorld("paranoia", {
  engine: (req) => ipcRenderer.invoke("engine:request", req),
  openDialog: () => ipcRenderer.invoke("dialog:open"),
  info: () => ipcRenderer.invoke("app:info"),
  reveal: (p) => ipcRenderer.invoke("app:reveal", p),
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
  onEngineRestarted: (cb) => {
    const h = (_e, r) => cb(r);
    ipcRenderer.on("engine:restarted", h);
    return () => ipcRenderer.removeListener("engine:restarted", h);
  },
});
