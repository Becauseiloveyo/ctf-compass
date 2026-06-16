const fs = require("fs");
const path = require("path");
const vm = require("vm");

const root = path.resolve(__dirname, "..");
const requiredFiles = [
  "desktop/main.js",
  "desktop/preload.js",
  "desktop/ctf2-connector.js",
  "desktop/renderer/renderer.js",
  "desktop/renderer/web-polyfill.js",
  "desktop/renderer/index.html",
  "desktop/renderer/styles.css",
  "desktop/renderer/product-ui.css",
  "desktop/renderer/compact-ui.css",
  "desktop/renderer/sidebar-stable.css",
];

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function read(relPath) {
  const fullPath = path.join(root, relPath);
  assert(fs.existsSync(fullPath), `Missing required file: ${relPath}`);
  return fs.readFileSync(fullPath, "utf8");
}

for (const file of requiredFiles) read(file);

for (const file of [
  "desktop/renderer/renderer.js",
  "desktop/renderer/web-polyfill.js",
  "desktop/preload.js",
  "desktop/ctf2-connector.js",
  "desktop/main.js",
]) {
  try {
    new vm.Script(read(file), { filename: file });
  } catch (error) {
    throw new Error(`${file} has a syntax error: ${error.message}`);
  }
}

const preload = read("desktop/preload.js");
[
  "getCtf2Status",
  "importCtf2Token",
  "listCtf2Challenges",
  "importCtf2Challenge",
  "checkForUpdates",
  "clearCtf2Data",
  "getCtf2History",
  "revealCtf2Downloads",
].forEach((apiName) => {
  assert(preload.includes(apiName), `preload.js does not expose ${apiName}`);
});

const main = read("desktop/main.js");
[
  "ctf2-status",
  "ctf2-import-token",
  "ctf2-list-challenges",
  "ctf2-import-challenge",
  "ctf2-history",
  "ctf2-clear-data",
  "ctf2-reveal-downloads",
  "check-for-updates",
].forEach((channel) => {
  assert(main.includes(channel), `main.js is missing IPC channel ${channel}`);
});

const webPolyfill = read("desktop/renderer/web-polyfill.js");
[
  "installCtf2ConnectorUi",
  "installSelectSkins",
  "ctf2-category-select",
  "web-max-pages-select",
  "check-update-button",
].forEach((needle) => {
  assert(webPolyfill.includes(needle), `web-polyfill.js is missing ${needle}`);
});

console.log("desktop smoke test passed");
