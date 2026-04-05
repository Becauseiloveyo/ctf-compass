const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("ctfCompass", {
  analyzeChallenge: (payload) => ipcRenderer.invoke("analyze-challenge", payload),
  getMeta: () => ipcRenderer.invoke("app-meta"),
});

