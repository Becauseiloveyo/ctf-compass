const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("linkLauncher", {
  openExternal: (payload) => ipcRenderer.invoke("open-external-link", payload),
  notify: (payload) => ipcRenderer.invoke("show-notification", payload),
  getMeta: () => ipcRenderer.invoke("launcher-meta"),
});
