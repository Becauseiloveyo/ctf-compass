const { app, BrowserWindow, Notification, ipcMain, shell } = require("electron");
const path = require("path");

const ALLOWED_PROTOCOLS = new Set([
  "http:",
  "https:",
  "taobao:",
  "tbopen:",
  "tmall:",
  "openapp.jdmobile:",
  "jingdong:",
  "pinduoduo:",
  "pddopen:",
  "railway12306:",
  "cn.12306:",
]);

function createWindow() {
  const win = new BrowserWindow({
    width: 1180,
    height: 780,
    minWidth: 980,
    minHeight: 660,
    backgroundColor: "#f4f7f8",
    title: "Link Launcher",
    autoHideMenuBar: true,
    show: false,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  win.once("ready-to-show", () => {
    win.show();
  });

  win.loadFile(path.join(__dirname, "renderer", "index.html"));
}

function normalizeExternalUrl(value) {
  const trimmed = String(value || "").trim();
  if (!trimmed) {
    throw new Error("链接不能为空。");
  }

  const hasProtocol = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed);
  const target = hasProtocol ? trimmed : `https://${trimmed}`;
  const parsed = new URL(target);
  const protocol = parsed.protocol.toLowerCase();

  if (!ALLOWED_PROTOCOLS.has(protocol)) {
    throw new Error("仅支持 http/https 和常见官方 App 跳转协议。");
  }

  return target;
}

ipcMain.handle("open-external-link", async (_event, payload) => {
  const url = normalizeExternalUrl(payload?.url);
  await shell.openExternal(url, { activate: true });
  return { opened: true, url };
});

ipcMain.handle("show-notification", async (_event, payload) => {
  if (!Notification.isSupported()) {
    return { shown: false };
  }

  new Notification({
    title: String(payload?.title || "Link Launcher"),
    body: String(payload?.body || ""),
    silent: false,
  }).show();

  return { shown: true };
});

ipcMain.handle("launcher-meta", async () => ({
  version: app.getVersion(),
  mode: app.isPackaged ? "packaged" : "development",
}));

app.whenReady().then(() => {
  createWindow();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});
