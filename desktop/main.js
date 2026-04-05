const { app, BrowserWindow, ipcMain } = require("electron");
const path = require("path");
const { spawn } = require("child_process");

const isDev = !app.isPackaged;

function createWindow() {
  const mainWindow = new BrowserWindow({
    width: 1480,
    height: 980,
    minWidth: 1200,
    minHeight: 760,
    backgroundColor: "#07111f",
    title: "CTF Compass",
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  mainWindow.loadFile(path.join(__dirname, "renderer", "index.html"));
}

function resolvePythonCommand() {
  if (process.platform === "win32") {
    return ["python", []];
  }
  return ["python3", []];
}

function runBridge(payload) {
  const [command, prefixArgs] = resolvePythonCommand();
  const args = [
    ...prefixArgs,
    "-m",
    "ctf_compass.bridge",
    "--title",
    payload.title,
    "--description",
    payload.description,
    "--lang",
    payload.lang || "zh-CN",
    "--tags",
    ...payload.tags,
  ];

  const env = {
    ...process.env,
    PYTHONPATH: path.join(app.getAppPath(), "src"),
  };

  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: app.getAppPath(),
      env,
      windowsHide: true,
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });

    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    child.on("error", (error) => {
      reject(new Error(`Failed to start Python bridge: ${error.message}`));
    });

    child.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(stderr.trim() || `Python bridge exited with code ${code}`));
        return;
      }

      try {
        resolve(JSON.parse(stdout));
      } catch (error) {
        reject(new Error(`Invalid bridge JSON: ${error.message}`));
      }
    });
  });
}

ipcMain.handle("analyze-challenge", async (_event, payload) => runBridge(payload));
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
