const fs = require("fs");
const path = require("path");

const projectRoot = path.resolve(__dirname, "..");
const releaseDir = path.join(projectRoot, "release");
const { version } = require(path.join(projectRoot, "package.json"));
const keepName = `CTF-Compass-${version}-win-x64.zip`;

if (!fs.existsSync(releaseDir)) {
  process.exit(0);
}

fs.readdirSync(releaseDir)
  .filter((name) => /^CTF-Compass-.*-win-x64\.zip$/.test(name))
  .filter((name) => name !== keepName)
  .forEach((name) => {
    const targetPath = path.join(releaseDir, name);
    fs.unlinkSync(targetPath);
    process.stdout.write(`Removed old release artifact: ${name}\n`);
  });
