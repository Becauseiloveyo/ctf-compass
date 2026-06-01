const fs = require("fs");
const path = require("path");
const { spawn, spawnSync } = require("child_process");

const DEFAULT_TIMEOUT_MS = 90_000;
const LONG_TIMEOUT_MS = 240_000;
const MAX_OUTPUT_BYTES = 768 * 1024;
const MAX_COLLECTED_FILES = 80;
const TOOL_CACHE_MS = 8_000;

const TOOL_DEFINITIONS = {
  exiftool: {
    label: "ExifTool",
    command: "exiftool",
    homepage: "https://exiftool.org/",
    installHint: "安装 ExifTool 并加入 PATH。Windows 可用 scoop/choco，或从 exiftool.org 下载。",
    purpose: "读取图片、文档、音频和二进制文件元数据。",
  },
  binwalk: {
    label: "binwalk",
    command: "binwalk",
    homepage: "https://github.com/ReFirmLabs/binwalk",
    installHint: "安装 binwalk 并加入 PATH。Windows 推荐 WSL/Kali，或 Python/Rust 发行版。",
    purpose: "扫描文件签名，发现嵌入文件和可提取分区。",
  },
  zsteg: {
    label: "zsteg",
    command: "zsteg",
    homepage: "https://github.com/zed-0xff/zsteg",
    installHint: "安装 Ruby 后执行 gem install zsteg，并确保 zsteg 在 PATH 中。",
    purpose: "检测 PNG/BMP 的 LSB 隐写数据。",
  },
  tshark: {
    label: "TShark",
    command: "tshark",
    homepage: "https://www.wireshark.org/docs/man-pages/tshark",
    installHint: "安装 Wireshark，并在安装时选择 TShark / 加入 PATH。",
    purpose: "命令行解析 pcap/pcapng，提取 HTTP、DNS 和对象。",
  },
  ciphey: {
    label: "Ciphey",
    command: "ciphey",
    homepage: "https://github.com/Ciphey/Ciphey",
    installHint: "安装 Python/pipx 后执行 pipx install ciphey，并确保 ciphey 在 PATH 中。",
    purpose: "自动尝试多层编码、古典密码和常见弱加密。",
  },
  rabin2: {
    label: "rabin2",
    command: "rabin2",
    homepage: "https://github.com/radareorg/radare2",
    installHint: "安装 radare2，并确保 rabin2 在 PATH 中。",
    purpose: "提取 ELF/PE/Mach-O 头、section、imports 和 strings。",
  },
  jadx: {
    label: "jadx",
    command: "jadx",
    homepage: "https://github.com/skylot/jadx",
    installHint: "安装 Java 17+ 和 jadx，或使用 scoop install jadx。",
    purpose: "把 APK/DEX 反编译为 Java 源码和资源视图。",
  },
  apktool: {
    label: "apktool",
    command: "apktool",
    homepage: "https://apktool.org/",
    installHint: "安装 Java 和 apktool，或使用 scoop/choco 安装 apktool。",
    purpose: "解包 APK 资源、Manifest 和 smali。",
  },
};

let statusCache = null;
let statusCacheAt = 0;

function sanitizeSegment(value) {
  return String(value || "")
    .replace(/[<>:"/\\|?*\x00-\x1f]/g, "_")
    .replace(/\s+/g, "-")
    .slice(0, 80);
}

function ensureDir(targetPath) {
  fs.mkdirSync(targetPath, { recursive: true });
}

function writeTextFile(outputRoot, name, content) {
  ensureDir(outputRoot);
  const targetPath = path.join(outputRoot, name);
  fs.writeFileSync(targetPath, content.endsWith("\n") ? content : `${content}\n`, "utf8");
  return targetPath;
}

function formatBytes(size) {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / (1024 * 1024)).toFixed(1)} MB`;
}

function trimOutput(value) {
  const buffer = Buffer.from(String(value || ""), "utf8");
  if (buffer.length <= MAX_OUTPUT_BYTES) {
    return buffer.toString("utf8");
  }
  return `${buffer.subarray(0, MAX_OUTPUT_BYTES).toString("utf8")}\n\n[output truncated at ${formatBytes(MAX_OUTPUT_BYTES)}]\n`;
}

function findExecutable(command) {
  const lookup = process.platform === "win32" ? "where.exe" : "which";
  const result = spawnSync(lookup, [command], {
    encoding: "utf8",
    windowsHide: true,
    timeout: 4_000,
  });

  if (result.status !== 0) {
    return null;
  }

  return (
    String(result.stdout || "")
      .split(/\r?\n/)
      .map((item) => item.trim())
      .filter(Boolean)[0] || null
  );
}

function detectToolStatus(refresh = false) {
  const now = Date.now();
  if (!refresh && statusCache && now - statusCacheAt < TOOL_CACHE_MS) {
    return statusCache;
  }

  statusCache = Object.entries(TOOL_DEFINITIONS).reduce((accumulator, [id, definition]) => {
    const executablePath = findExecutable(definition.command);
    accumulator[id] = {
      id,
      label: definition.label,
      command: definition.command,
      available: Boolean(executablePath),
      path: executablePath,
      homepage: definition.homepage,
      installHint: definition.installHint,
      purpose: definition.purpose,
    };
    return accumulator;
  }, {});
  statusCacheAt = now;
  return statusCache;
}

function getToolStatusSummary(refresh = false) {
  const status = detectToolStatus(refresh);
  const items = Object.values(status);
  return {
    installed: items.filter((item) => item.available),
    missing: items.filter((item) => !item.available),
  };
}

function artifactExt(artifact) {
  return String(artifact.extension || path.extname(artifact.path || artifact.name || "") || "").toLowerCase();
}

function isImageArtifact(artifact) {
  return artifact.family === "image" || [".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp", ".tiff"].includes(artifactExt(artifact));
}

function isPngOrBmp(artifact) {
  return [".png", ".bmp"].includes(artifactExt(artifact)) || ["PNG", "BMP"].includes(String(artifact.badge || "").toUpperCase());
}

function isTextLikeArtifact(artifact) {
  return artifact.family === "text" || [".txt", ".log", ".csv", ".json", ".xml", ".html"].includes(artifactExt(artifact));
}

function isTrafficArtifact(artifact) {
  return artifact.family === "network" || [".pcap", ".pcapng", ".cap"].includes(artifactExt(artifact));
}

function isArchiveOrUnknown(artifact) {
  return ["archive", "unknown", "binary", "image", "document"].includes(artifact.family);
}

function isAndroidArtifact(artifact) {
  return artifactExt(artifact) === ".apk" || String(artifact.badge || "").toUpperCase() === "APK";
}

function isNativeBinaryArtifact(artifact) {
  const badge = String(artifact.badge || "").toUpperCase();
  return artifact.family === "binary" && (["ELF", "PE", "MACH-O"].includes(badge) || [".exe", ".dll", ".so", ".elf"].includes(artifactExt(artifact)));
}

function quoteCommand(command, args) {
  return [command, ...args].map((part) => (/\s/.test(String(part)) ? `"${part}"` : String(part))).join(" ");
}

function runCommand(command, args, options = {}) {
  const timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;
  return new Promise((resolve, reject) => {
    const startedAt = Date.now();
    const useShell = process.platform === "win32" && /\.(cmd|bat)$/i.test(command);
    const child = spawn(command, args, {
      cwd: options.cwd,
      windowsHide: true,
      shell: useShell,
    });

    let stdout = "";
    let stderr = "";
    let killedByTimeout = false;

    const timer = setTimeout(() => {
      killedByTimeout = true;
      child.kill("SIGKILL");
    }, timeoutMs);

    child.stdout.on("data", (chunk) => {
      stdout = trimOutput(stdout + chunk.toString("utf8"));
    });
    child.stderr.on("data", (chunk) => {
      stderr = trimOutput(stderr + chunk.toString("utf8"));
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      resolve({
        code,
        signal,
        stdout,
        stderr,
        timedOut: killedByTimeout,
        durationMs: Date.now() - startedAt,
        commandLine: quoteCommand(command, args),
      });
    });
  });
}

function formatRunReport(title, run) {
  const lines = [
    `# ${title}`,
    "",
    `Command: ${run.commandLine}`,
    `Exit: ${run.timedOut ? "timeout" : run.code}`,
    `Duration: ${(run.durationMs / 1000).toFixed(1)}s`,
    "",
    "## stdout",
    run.stdout.trim() || "(empty)",
    "",
    "## stderr",
    run.stderr.trim() || "(empty)",
    "",
  ];
  return lines.join("\n");
}

function collectFilesDeep(rootPath, limit = MAX_COLLECTED_FILES) {
  if (!fs.existsSync(rootPath)) {
    return [];
  }

  const collected = [];
  const stack = [rootPath];
  while (stack.length && collected.length < limit) {
    const current = stack.pop();
    let stat;
    try {
      stat = fs.statSync(current);
    } catch (_error) {
      continue;
    }

    if (stat.isDirectory()) {
      const children = fs.readdirSync(current).map((name) => path.join(current, name)).reverse();
      children.forEach((child) => stack.push(child));
      continue;
    }

    if (stat.isFile()) {
      collected.push(current);
    }
  }
  return collected;
}

function buildOutputName(filePath, suffix) {
  return `${sanitizeSegment(path.parse(filePath).name)}-${suffix}.txt`;
}

async function runSingleReport(action, filePath, outputRoot, status) {
  const args = action.args(filePath, outputRoot);
  const command = status.path || status.command;
  const run = await runCommand(command, args, {
    cwd: outputRoot,
    timeoutMs: action.timeoutMs,
  });
  const outPath = writeTextFile(outputRoot, buildOutputName(filePath, action.outputSuffix), formatRunReport(action.label, run));
  return {
    message: run.timedOut ? `${action.label} 超时，已保存已有输出。` : `${action.label} 已执行，输出已导入工作台。`,
    createdFiles: [outPath],
  };
}

async function runMultiReport(action, filePath, outputRoot, status) {
  const sections = [];
  const command = status.path || status.command;
  for (const item of action.commands(filePath, outputRoot)) {
    const run = await runCommand(command, item.args, {
      cwd: outputRoot,
      timeoutMs: item.timeoutMs || action.timeoutMs,
    });
    sections.push(formatRunReport(item.title, run));
  }
  const outPath = writeTextFile(outputRoot, buildOutputName(filePath, action.outputSuffix), sections.join("\n\n"));
  return {
    message: `${action.label} 已执行，输出已导入工作台。`,
    createdFiles: [outPath],
  };
}

async function runDirectoryTool(action, filePath, outputRoot, status) {
  const directory = path.join(outputRoot, `${sanitizeSegment(path.parse(filePath).name)}-${action.outputSuffix}`);
  ensureDir(directory);
  const args = action.args(filePath, directory);
  const command = status.path || status.command;
  const run = await runCommand(command, args, {
    cwd: outputRoot,
    timeoutMs: action.timeoutMs || LONG_TIMEOUT_MS,
  });
  const discovered = collectFilesDeep(directory, action.collectLimit || 40);
  const manifest = [
    formatRunReport(action.label, run),
    "",
    "## generated files",
    discovered.length ? discovered.map((item) => path.relative(outputRoot, item)).join("\n") : "(none)",
    "",
  ].join("\n");
  const manifestPath = writeTextFile(outputRoot, buildOutputName(filePath, `${action.outputSuffix}-manifest`), manifest);
  return {
    message: discovered.length ? `${action.label} 已生成 ${discovered.length} 个文件，并创建清单。` : `${action.label} 已执行，但没有发现可导入的新文件。`,
    createdFiles: [manifestPath, ...discovered],
  };
}

const TOOL_ACTIONS = [
  {
    id: "tool:exiftool:metadata",
    tool: "exiftool",
    label: "ExifTool 元数据",
    outputSuffix: "exiftool",
    autoRun: true,
    appliesTo: (artifact) => isImageArtifact(artifact) || ["document", "audio", "binary", "archive", "unknown"].includes(artifact.family),
    args: (filePath) => ["-a", "-u", "-g1", filePath],
    runner: runSingleReport,
  },
  {
    id: "tool:binwalk:scan",
    tool: "binwalk",
    label: "binwalk 签名扫描",
    outputSuffix: "binwalk-scan",
    autoRun: true,
    appliesTo: isArchiveOrUnknown,
    args: (filePath) => [filePath],
    runner: runSingleReport,
  },
  {
    id: "tool:binwalk:extract",
    tool: "binwalk",
    label: "binwalk 提取嵌入文件",
    outputSuffix: "binwalk-extract",
    autoRun: true,
    appliesTo: isArchiveOrUnknown,
    args: (filePath, directory) => ["-e", "-C", directory, filePath],
    collectLimit: 60,
    timeoutMs: LONG_TIMEOUT_MS,
    runner: runDirectoryTool,
  },
  {
    id: "tool:zsteg:scan",
    tool: "zsteg",
    label: "zsteg LSB 扫描",
    outputSuffix: "zsteg",
    autoRun: true,
    appliesTo: isPngOrBmp,
    args: (filePath) => ["-a", filePath],
    timeoutMs: LONG_TIMEOUT_MS,
    runner: runSingleReport,
  },
  {
    id: "tool:ciphey:decode",
    tool: "ciphey",
    label: "Ciphey 自动解码",
    outputSuffix: "ciphey",
    autoRun: true,
    appliesTo: isTextLikeArtifact,
    args: (filePath) => ["-q", "-f", filePath],
    timeoutMs: LONG_TIMEOUT_MS,
    runner: runSingleReport,
  },
  {
    id: "tool:tshark:http",
    tool: "tshark",
    label: "TShark HTTP 提取",
    outputSuffix: "tshark-http",
    autoRun: true,
    appliesTo: isTrafficArtifact,
    args: (filePath) => [
      "-r",
      filePath,
      "-Y",
      "http",
      "-T",
      "fields",
      "-e",
      "frame.number",
      "-e",
      "ip.src",
      "-e",
      "ip.dst",
      "-e",
      "http.host",
      "-e",
      "http.request.method",
      "-e",
      "http.request.uri",
      "-e",
      "http.cookie",
      "-E",
      "header=y",
      "-E",
      "separator=\t",
    ],
    runner: runSingleReport,
  },
  {
    id: "tool:tshark:dns",
    tool: "tshark",
    label: "TShark DNS 提取",
    outputSuffix: "tshark-dns",
    autoRun: true,
    appliesTo: isTrafficArtifact,
    args: (filePath) => [
      "-r",
      filePath,
      "-Y",
      "dns",
      "-T",
      "fields",
      "-e",
      "frame.number",
      "-e",
      "ip.src",
      "-e",
      "dns.qry.name",
      "-e",
      "dns.a",
      "-E",
      "header=y",
      "-E",
      "separator=\t",
    ],
    runner: runSingleReport,
  },
  {
    id: "tool:tshark:objects-http",
    tool: "tshark",
    label: "TShark 导出 HTTP 对象",
    outputSuffix: "tshark-http-objects",
    autoRun: false,
    appliesTo: isTrafficArtifact,
    args: (filePath, directory) => ["-r", filePath, "--export-objects", `http,${directory}`],
    collectLimit: 60,
    timeoutMs: LONG_TIMEOUT_MS,
    runner: runDirectoryTool,
  },
  {
    id: "tool:rabin2:triage",
    tool: "rabin2",
    label: "rabin2 二进制三件套",
    outputSuffix: "rabin2",
    autoRun: true,
    appliesTo: isNativeBinaryArtifact,
    commands: (filePath) => [
      { title: "rabin2 header", args: ["-I", filePath] },
      { title: "rabin2 sections", args: ["-S", filePath] },
      { title: "rabin2 imports", args: ["-i", filePath] },
      { title: "rabin2 strings", args: ["-z", filePath] },
    ],
    runner: runMultiReport,
  },
  {
    id: "tool:jadx:decompile",
    tool: "jadx",
    label: "jadx 反编译 APK",
    outputSuffix: "jadx",
    autoRun: false,
    appliesTo: isAndroidArtifact,
    args: (filePath, directory) => ["-d", directory, filePath],
    collectLimit: 30,
    timeoutMs: LONG_TIMEOUT_MS,
    runner: runDirectoryTool,
  },
  {
    id: "tool:apktool:decode",
    tool: "apktool",
    label: "apktool 解包资源",
    outputSuffix: "apktool",
    autoRun: false,
    appliesTo: isAndroidArtifact,
    args: (filePath, directory) => ["d", "-f", "-o", directory, filePath],
    collectLimit: 40,
    timeoutMs: LONG_TIMEOUT_MS,
    runner: runDirectoryTool,
  },
];

function isToolActionAutoRunnable(actionId) {
  const action = TOOL_ACTIONS.find((item) => item.id === actionId);
  return Boolean(action?.autoRun);
}

function getToolActionsForArtifact(artifact, refresh = false) {
  const status = detectToolStatus(refresh);
  return TOOL_ACTIONS.filter((action) => action.appliesTo(artifact)).map((action) => {
    const toolStatus = status[action.tool];
    return {
      id: action.id,
      label: action.label,
      tool: action.tool,
      toolLabel: toolStatus.label,
      available: toolStatus.available,
      executablePath: toolStatus.path,
      installHint: toolStatus.installHint,
      homepage: toolStatus.homepage,
      purpose: toolStatus.purpose,
      autoRun: action.autoRun,
      kind: "external-tool",
    };
  });
}

async function runToolAction(actionId, filePath, outputRoot) {
  const action = TOOL_ACTIONS.find((item) => item.id === actionId);
  if (!action) {
    throw new Error(`Unsupported tool action: ${actionId}`);
  }

  if (!filePath || !fs.existsSync(filePath)) {
    throw new Error("目标附件不存在。");
  }

  ensureDir(outputRoot);
  const status = detectToolStatus(true)[action.tool];
  if (!status || !status.available) {
    const definition = TOOL_DEFINITIONS[action.tool];
    throw new Error(`未检测到 ${definition.label}。${definition.installHint}`);
  }

  const result = await action.runner(action, filePath, outputRoot, status);
  return {
    message: result.message,
    createdFiles: result.createdFiles.filter((item) => fs.existsSync(item) && fs.statSync(item).isFile()),
  };
}

function getToolReferences() {
  return Object.entries(TOOL_DEFINITIONS).map(([id, item]) => ({
    id,
    label: item.label,
    homepage: item.homepage,
    purpose: item.purpose,
    installHint: item.installHint,
  }));
}

module.exports = {
  getToolActionsForArtifact,
  getToolReferences,
  getToolStatusSummary,
  isToolActionAutoRunnable,
  runToolAction,
};
