const fs = require("fs");
const { app, BrowserWindow, dialog, ipcMain, shell } = require("electron");
const path = require("path");
const { analyzeChallenge, prepareArtifactsFromEntries, runArtifactAction } = require("./analyzer");

const isDev = !app.isPackaged;

function createWindow() {
  const mainWindow = new BrowserWindow({
    width: 1500,
    height: 980,
    minWidth: 1240,
    minHeight: 780,
    backgroundColor: "#eef2f4",
    title: "CTF Compass",
    autoHideMenuBar: true,
    show: false,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  mainWindow.once("ready-to-show", () => {
    mainWindow.show();
  });

  mainWindow.loadFile(path.join(__dirname, "renderer", "index.html"));
}

function buildRunOutputRoot() {
  return path.join(app.getPath("userData"), "generated", `analysis-${Date.now()}`);
}

function workspaceFilePath() {
  return path.join(app.getPath("userData"), "workspace", "current-session.json");
}

function ensureParentDir(targetPath) {
  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
}

async function selectFiles() {
  const result = await dialog.showOpenDialog({
    title: "Select challenge files",
    properties: ["openFile", "multiSelections"],
  });

  if (result.canceled) {
    return [];
  }

  return prepareArtifactsFromEntries(result.filePaths);
}

async function selectFolder() {
  const result = await dialog.showOpenDialog({
    title: "Select challenge folder",
    properties: ["openDirectory"],
  });

  if (result.canceled || !result.filePaths.length) {
    return [];
  }

  return prepareArtifactsFromEntries(result.filePaths);
}

ipcMain.handle("pick-files", async () => selectFiles());
ipcMain.handle("pick-folder", async () => selectFolder());
ipcMain.handle("prepare-artifacts", async (_event, entryPaths) => prepareArtifactsFromEntries(entryPaths || []));
ipcMain.handle("analyze-challenge", async (_event, payload) => analyzeChallenge(payload || {}, buildRunOutputRoot()));
ipcMain.handle("run-artifact-action", async (_event, payload) =>
  runArtifactAction(payload?.actionId, payload?.filePath, buildRunOutputRoot()),
);
ipcMain.handle("reveal-artifact", async (_event, targetPath) => {
  if (targetPath) {
    shell.showItemInFolder(targetPath);
  }
});
ipcMain.handle("load-workspace", async () => {
  const targetPath = workspaceFilePath();
  if (!fs.existsSync(targetPath)) {
    return null;
  }

  return JSON.parse(fs.readFileSync(targetPath, "utf8"));
});
ipcMain.handle("save-workspace", async (_event, payload) => {
  const targetPath = workspaceFilePath();
  ensureParentDir(targetPath);
  fs.writeFileSync(targetPath, `${JSON.stringify(payload || {}, null, 2)}\n`, "utf8");
  return { path: targetPath };
});
ipcMain.handle("clear-workspace", async () => {
  const targetPath = workspaceFilePath();
  if (fs.existsSync(targetPath)) {
    fs.unlinkSync(targetPath);
  }
  return { cleared: true };
});
ipcMain.handle("export-report", async (_event, payload) => {
  const suggestedName = String(payload?.suggestedName || "ctf-compass-report.md");
  const content = String(payload?.content || "");
  const result = await dialog.showSaveDialog({
    title: "Export Markdown report",
    defaultPath: path.join(app.getPath("documents"), suggestedName),
    filters: [
      { name: "Markdown", extensions: ["md"] },
      { name: "Text", extensions: ["txt"] },
    ],
  });

  if (result.canceled || !result.filePath) {
    return { canceled: true };
  }

  ensureParentDir(result.filePath);
  fs.writeFileSync(result.filePath, content, "utf8");
  return { filePath: result.filePath };
});
ipcMain.handle("app-meta", async () => ({
  version: app.getVersion(),
  packaged: app.isPackaged,
  mode: isDev ? "development" : "production",
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
