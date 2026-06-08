const fs = require("fs");
const path = require("path");
const zlib = require("zlib");
const AdmZip = require("adm-zip");
const { analyzeChallenge } = require("../desktop/analyzer");

const DEFAULT_SAMPLE = path.resolve(__dirname, "..", "tmp", "input", "a05ed035-b476-49d6-9b32-462ff13c5944.zip");
const DEFAULT_EXPECTED_FLAG = "flag{96efd0a2037d06f34199e921079778ee}";

function fail(message) {
  console.error(message);
  process.exitCode = 1;
}

function resetDir(dirPath) {
  fs.rmSync(dirPath, { recursive: true, force: true });
  fs.mkdirSync(dirPath, { recursive: true });
}

function writeText(filePath, content) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, content);
  return filePath;
}

function collectFlags(result) {
  return (result.flagCandidates || []).map((item) => item.value);
}

async function runCase(root, name, payload, expectedFlag) {
  const outputRoot = path.join(root, `${name}-out`);
  const result = await analyzeChallenge(payload, outputRoot);
  const flags = collectFlags(result);

  if (!flags.includes(expectedFlag)) {
    throw new Error(`case ${name}: expected ${expectedFlag}, got ${flags.join(", ") || "no flags"}`);
  }

  if (result.pipelineErrors && result.pipelineErrors.length) {
    throw new Error(`case ${name}: unexpected pipeline errors: ${JSON.stringify(result.pipelineErrors, null, 2)}`);
  }

  return {
    name,
    status: result.solver?.status,
    primaryFlag: result.solver?.primaryFlag?.value,
    actionsRun: result.solver?.actionsRun,
    artifacts: result.challenge?.artifactCount,
  };
}

async function runPwnCase(root, elfPath, expectedFlag) {
  const outputRoot = path.join(root, "pwn-elf-static-out");
  const result = await analyzeChallenge(
    {
      title: "synthetic pwn ELF smoke",
      description: "Validate checksec-lite, risky imports, and short ROP gadget detection.",
      tags: ["pwn", "elf", "rop"],
      artifacts: [elfPath],
    },
    outputRoot,
  );
  const flags = collectFlags(result);
  if (!flags.includes(expectedFlag)) {
    throw new Error(`case pwn-elf-static: expected ${expectedFlag}, got ${flags.join(", ") || "no flags"}`);
  }
  if (result.pipelineErrors && result.pipelineErrors.length) {
    throw new Error(`case pwn-elf-static: unexpected pipeline errors: ${JSON.stringify(result.pipelineErrors, null, 2)}`);
  }
  if (result.classification?.id !== "pwn") {
    throw new Error(`case pwn-elf-static: expected pwn classification, got ${result.classification?.id || "unknown"}`);
  }

  const elfArtifact = result.artifacts.find((artifact) => artifact.path === elfPath);
  const highlightText = (elfArtifact?.highlights || []).join("\n");
  if (!/checksec-lite: RELRO=full NX=on PIE=on Canary=yes/.test(highlightText)) {
    throw new Error(`case pwn-elf-static: missing expected checksec highlight: ${highlightText}`);
  }
  const keywordText = (elfArtifact?.keywords || []).join(" ");
  if (!/gets/.test(highlightText) || !/\brop\b/.test(keywordText) || !/\bgadget\b/.test(keywordText)) {
    throw new Error(`case pwn-elf-static: missing risky function highlight or gadget keywords: ${highlightText}\n${keywordText}`);
  }

  const generatedPaths = result.pipelineLog.flatMap((entry) => entry.createdArtifacts.map((artifact) => artifact.path));
  const checksecPath = generatedPaths.find((filePath) => filePath.endsWith("-checksec-lite.txt"));
  const surfacePath = generatedPaths.find((filePath) => filePath.endsWith("-pwn-surface.txt"));
  const pathsPath = generatedPaths.find((filePath) => filePath.endsWith("-pwn-paths.txt"));
  const gadgetPath = generatedPaths.find((filePath) => filePath.endsWith("-rop-gadgets-lite.txt"));
  if (!checksecPath || !surfacePath || !pathsPath || !gadgetPath) {
    throw new Error(`case pwn-elf-static: missing generated pwn reports: ${generatedPaths.join(", ")}`);
  }
  if (!/RELRO: full/.test(fs.readFileSync(checksecPath, "utf8")) || !/gets: critical/.test(fs.readFileSync(surfacePath, "utf8"))) {
    throw new Error("case pwn-elf-static: generated checksec or pwn surface report is incomplete");
  }
  if (!/stack overflow \/ ret2libc \/ ROP/.test(fs.readFileSync(pathsPath, "utf8"))) {
    throw new Error("case pwn-elf-static: generated pwn path report is incomplete");
  }
  if (!/pop rdi; ret/.test(fs.readFileSync(gadgetPath, "utf8"))) {
    throw new Error("case pwn-elf-static: generated gadget report is incomplete");
  }

  return {
    name: "pwn-elf-static",
    status: result.solver?.status,
    primaryFlag: result.solver?.primaryFlag?.value,
    actionsRun: result.solver?.actionsRun,
    artifacts: result.challenge?.artifactCount,
  };
}

function markZipAsPseudoEncrypted(zipPath) {
  const buffer = fs.readFileSync(zipPath);
  let offset = 0;

  while (offset + 4 <= buffer.length) {
    const signature = buffer.readUInt32LE(offset);

    if (signature === 0x04034b50 && offset + 30 <= buffer.length) {
      const flags = buffer.readUInt16LE(offset + 6);
      buffer.writeUInt16LE(flags | 0x0001, offset + 6);
      const nameLength = buffer.readUInt16LE(offset + 26);
      const extraLength = buffer.readUInt16LE(offset + 28);
      offset += Math.max(4, 30 + nameLength + extraLength);
      continue;
    }

    if (signature === 0x02014b50 && offset + 46 <= buffer.length) {
      const flags = buffer.readUInt16LE(offset + 8);
      buffer.writeUInt16LE(flags | 0x0001, offset + 8);
      const nameLength = buffer.readUInt16LE(offset + 28);
      const extraLength = buffer.readUInt16LE(offset + 30);
      const commentLength = buffer.readUInt16LE(offset + 32);
      offset += Math.max(4, 46 + nameLength + extraLength + commentLength);
      continue;
    }

    offset += 1;
  }

  fs.writeFileSync(zipPath, buffer);
}

function createZipWithComment(zipPath, flag) {
  const zip = new AdmZip();
  zip.addFile("note.txt", Buffer.from("zip comment smoke fixture\n"));
  zip.addZipComment(flag);
  fs.mkdirSync(path.dirname(zipPath), { recursive: true });
  zip.writeZip(zipPath);
  return zipPath;
}

function createPseudoEncryptedZip(zipPath, flag) {
  const zip = new AdmZip();
  zip.addFile("flag.txt", Buffer.from(`${flag}\n`));
  fs.mkdirSync(path.dirname(zipPath), { recursive: true });
  zip.writeZip(zipPath);
  markZipAsPseudoEncrypted(zipPath);
  return zipPath;
}

function writeTarField(header, offset, length, value) {
  const buffer = Buffer.from(String(value), "ascii");
  buffer.copy(header, offset, 0, Math.min(buffer.length, length));
}

function writeTarOctal(header, offset, length, value) {
  const text = Math.max(0, Number(value) || 0)
    .toString(8)
    .padStart(length - 1, "0")
    .slice(-(length - 1));
  writeTarField(header, offset, length, `${text}\0`);
}

function createTarBuffer(entries) {
  const chunks = [];
  entries.forEach((entry) => {
    const data = Buffer.isBuffer(entry.data) ? entry.data : Buffer.from(entry.data, "utf8");
    const header = Buffer.alloc(512);
    writeTarField(header, 0, 100, entry.name);
    writeTarOctal(header, 100, 8, 0o644);
    writeTarOctal(header, 108, 8, 0);
    writeTarOctal(header, 116, 8, 0);
    writeTarOctal(header, 124, 12, data.length);
    writeTarOctal(header, 136, 12, Math.floor(Date.now() / 1000));
    header.fill(32, 148, 156);
    writeTarField(header, 156, 1, "0");
    writeTarField(header, 257, 6, "ustar\0");
    writeTarField(header, 263, 2, "00");
    let checksum = 0;
    for (const byte of header) checksum += byte;
    writeTarOctal(header, 148, 8, checksum);
    chunks.push(header, data, Buffer.alloc((512 - (data.length % 512)) % 512));
  });
  chunks.push(Buffer.alloc(1024));
  return Buffer.concat(chunks);
}

function createTgz(tgzPath, flag) {
  const tar = createTarBuffer([
    { name: "clues/readme.txt", data: "recursive tar smoke fixture\n" },
    { name: "nested/flag.txt", data: `${flag}\n` },
  ]);
  fs.mkdirSync(path.dirname(tgzPath), { recursive: true });
  fs.writeFileSync(tgzPath, zlib.gzipSync(tar));
  return tgzPath;
}

function createBmpLsb(bmpPath, text, width = 32, height = 16) {
  const bits = Array.from(Buffer.from(text, "utf8")).flatMap((byte) => byte.toString(2).padStart(8, "0").split("").map(Number));
  if (bits.length > width * height) {
    throw new Error("BMP smoke fixture is too small for payload");
  }

  const bitsPerPixel = 24;
  const rowStride = Math.floor((bitsPerPixel * width + 31) / 32) * 4;
  const dataOffset = 54;
  const buffer = Buffer.alloc(dataOffset + rowStride * height);
  buffer.write("BM", 0, "ascii");
  buffer.writeUInt32LE(buffer.length, 2);
  buffer.writeUInt32LE(dataOffset, 10);
  buffer.writeUInt32LE(40, 14);
  buffer.writeInt32LE(width, 18);
  buffer.writeInt32LE(height, 22);
  buffer.writeUInt16LE(1, 26);
  buffer.writeUInt16LE(bitsPerPixel, 28);
  buffer.writeUInt32LE(0, 30);
  buffer.writeUInt32LE(rowStride * height, 34);

  for (let storedY = 0; storedY < height; storedY += 1) {
    const logicalY = height - 1 - storedY;
    for (let x = 0; x < width; x += 1) {
      const pixel = logicalY * width + x;
      const offset = dataOffset + storedY * rowStride + x * 3;
      buffer[offset] = 0x80 | (bits[pixel] || 0);
      buffer[offset + 1] = 0x80;
      buffer[offset + 2] = 0x80;
    }
  }

  fs.mkdirSync(path.dirname(bmpPath), { recursive: true });
  fs.writeFileSync(bmpPath, buffer);
  return bmpPath;
}

function createGifSplitComment(gifPath, chunks) {
  const header = Buffer.from("GIF89a", "ascii");
  const logicalScreen = Buffer.from([0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
  const commentParts = [Buffer.from([0x21, 0xfe])];
  chunks.forEach((chunk) => {
    const data = Buffer.from(chunk, "utf8");
    commentParts.push(Buffer.from([data.length]), data);
  });
  commentParts.push(Buffer.from([0x00, 0x3b]));
  fs.mkdirSync(path.dirname(gifPath), { recursive: true });
  fs.writeFileSync(gifPath, Buffer.concat([header, logicalScreen, ...commentParts]));
  return gifPath;
}

function align(value, alignment) {
  return Math.ceil(value / alignment) * alignment;
}

function createPwnElf64(filePath, flag) {
  const dynstrValues = ["", "libc.so.6", "gets", "printf", "system", "read", "__stack_chk_fail"];
  const dynstrOffsets = new Map();
  let dynstrLength = 0;
  const dynstrChunks = dynstrValues.map((value) => {
    dynstrOffsets.set(value, dynstrLength);
    const chunk = Buffer.from(`${value}\0`, "ascii");
    dynstrLength += chunk.length;
    return chunk;
  });
  const dynstr = Buffer.concat(dynstrChunks);

  const dynsym = Buffer.alloc(dynstrValues.length * 24);
  dynstrValues.slice(1).forEach((name, index) => {
    const offset = (index + 1) * 24;
    dynsym.writeUInt32LE(dynstrOffsets.get(name), offset);
    dynsym[offset + 4] = 0x12;
  });

  const rela = Buffer.alloc((dynstrValues.length - 1) * 24);
  dynstrValues.slice(1).forEach((_name, index) => {
    const offset = index * 24;
    rela.writeBigUInt64LE(BigInt(0x601000 + index * 8), offset);
    rela.writeBigUInt64LE((BigInt(index + 1) << 32n) | 7n, offset + 8);
  });

  const dynamic = Buffer.alloc(48);
  dynamic.writeBigUInt64LE(1n, 0);
  dynamic.writeBigUInt64LE(BigInt(dynstrOffsets.get("libc.so.6")), 8);
  dynamic.writeBigUInt64LE(24n, 16);
  dynamic.writeBigUInt64LE(0n, 24);
  dynamic.writeBigUInt64LE(0n, 32);
  dynamic.writeBigUInt64LE(0n, 40);

  const sectionNames = ["", ".text", ".rodata", ".interp", ".dynstr", ".dynsym", ".rela.plt", ".dynamic", ".note.GNU-stack", ".shstrtab"];
  const shstrOffsets = new Map();
  let shstrLength = 0;
  const shstr = Buffer.concat(
    sectionNames.map((name) => {
      shstrOffsets.set(name, shstrLength);
      const chunk = Buffer.from(`${name}\0`, "ascii");
      shstrLength += chunk.length;
      return chunk;
    }),
  );

  const sections = [
    { name: "", type: 0, flags: 0n, address: 0n, data: Buffer.alloc(0), align: 0, link: 0, info: 0, entrySize: 0 },
    { name: ".text", type: 1, flags: 6n, address: 0x401000n, data: Buffer.from([0x5f, 0xc3, 0x0f, 0x05, 0xc3, 0xc9, 0xc3, 0xc3]), align: 16, link: 0, info: 0, entrySize: 0 },
    { name: ".rodata", type: 1, flags: 2n, address: 0x402000n, data: Buffer.from(`${flag}\0`, "ascii"), align: 8, link: 0, info: 0, entrySize: 0 },
    { name: ".interp", type: 1, flags: 2n, address: 0x400200n, data: Buffer.from("/lib64/ld-linux-x86-64.so.2\0", "ascii"), align: 1, link: 0, info: 0, entrySize: 0 },
    { name: ".dynstr", type: 3, flags: 2n, address: 0x403000n, data: dynstr, align: 1, link: 0, info: 0, entrySize: 0 },
    { name: ".dynsym", type: 11, flags: 2n, address: 0x404000n, data: dynsym, align: 8, link: 4, info: 1, entrySize: 24 },
    { name: ".rela.plt", type: 4, flags: 2n, address: 0x405000n, data: rela, align: 8, link: 5, info: 1, entrySize: 24 },
    { name: ".dynamic", type: 6, flags: 3n, address: 0x406000n, data: dynamic, align: 8, link: 4, info: 0, entrySize: 16 },
    { name: ".note.GNU-stack", type: 1, flags: 0n, address: 0n, data: Buffer.alloc(0), align: 1, link: 0, info: 0, entrySize: 0 },
    { name: ".shstrtab", type: 3, flags: 0n, address: 0n, data: shstr, align: 1, link: 0, info: 0, entrySize: 0 },
  ];

  const programHeaderCount = 3;
  let cursor = align(64 + programHeaderCount * 56, 0x10);
  sections.slice(1).forEach((section) => {
    cursor = align(cursor, Math.max(1, section.align));
    section.offset = cursor;
    cursor += section.data.length;
  });
  const sectionHeaderOffset = align(cursor, 0x10);
  const buffer = Buffer.alloc(sectionHeaderOffset + sections.length * 64);

  buffer.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0);
  buffer.writeUInt16LE(3, 16);
  buffer.writeUInt16LE(62, 18);
  buffer.writeUInt32LE(1, 20);
  buffer.writeBigUInt64LE(0x401000n, 24);
  buffer.writeBigUInt64LE(64n, 32);
  buffer.writeBigUInt64LE(BigInt(sectionHeaderOffset), 40);
  buffer.writeUInt16LE(64, 52);
  buffer.writeUInt16LE(56, 54);
  buffer.writeUInt16LE(programHeaderCount, 56);
  buffer.writeUInt16LE(64, 58);
  buffer.writeUInt16LE(sections.length, 60);
  buffer.writeUInt16LE(9, 62);

  const writeProgramHeader = (index, type, flags, offset, address, fileSize, memorySize) => {
    const start = 64 + index * 56;
    buffer.writeUInt32LE(type, start);
    buffer.writeUInt32LE(flags, start + 4);
    buffer.writeBigUInt64LE(BigInt(offset), start + 8);
    buffer.writeBigUInt64LE(BigInt(address), start + 16);
    buffer.writeBigUInt64LE(BigInt(address), start + 24);
    buffer.writeBigUInt64LE(BigInt(fileSize), start + 32);
    buffer.writeBigUInt64LE(BigInt(memorySize), start + 40);
    buffer.writeBigUInt64LE(8n, start + 48);
  };
  const interp = sections[3];
  writeProgramHeader(0, 3, 4, interp.offset, interp.address, interp.data.length, interp.data.length);
  writeProgramHeader(1, 0x6474e551, 6, 0, 0, 0, 0);
  writeProgramHeader(2, 0x6474e552, 4, sections[7].offset, sections[7].address, sections[7].data.length, sections[7].data.length);

  sections.slice(1).forEach((section) => section.data.copy(buffer, section.offset));
  sections.forEach((section, index) => {
    const start = sectionHeaderOffset + index * 64;
    buffer.writeUInt32LE(shstrOffsets.get(section.name) || 0, start);
    buffer.writeUInt32LE(section.type, start + 4);
    buffer.writeBigUInt64LE(section.flags, start + 8);
    buffer.writeBigUInt64LE(section.address, start + 16);
    buffer.writeBigUInt64LE(BigInt(section.offset || 0), start + 24);
    buffer.writeBigUInt64LE(BigInt(section.data.length), start + 32);
    buffer.writeUInt32LE(section.link, start + 40);
    buffer.writeUInt32LE(section.info, start + 44);
    buffer.writeBigUInt64LE(BigInt(section.align || 0), start + 48);
    buffer.writeBigUInt64LE(BigInt(section.entrySize || 0), start + 56);
  });

  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, buffer);
  return filePath;
}

function createBrainfuckPrint(text) {
  let current = 0;
  let program = "";
  for (const char of text) {
    const target = char.charCodeAt(0);
    const up = (target - current + 256) & 0xff;
    const down = (current - target + 256) & 0xff;
    if (up <= down) {
      program += "+".repeat(up);
    } else {
      program += "-".repeat(down);
    }
    program += ".";
    current = target;
  }
  return program;
}

function brainfuckToOok(program) {
  const map = {
    ">": "Ook. Ook?",
    "<": "Ook? Ook.",
    "+": "Ook. Ook.",
    "-": "Ook! Ook!",
    ".": "Ook! Ook.",
    ",": "Ook. Ook!",
    "[": "Ook! Ook?",
    "]": "Ook? Ook!",
  };
  return Array.from(program).map((op) => map[op]).filter(Boolean).join(" ");
}

function affineEncode(text, multiplier, shift) {
  return String(text || "").replace(/[A-Za-z]/g, (char) => {
    const code = char.charCodeAt(0);
    const base = code >= 97 ? 97 : 65;
    const value = code - base;
    return String.fromCharCode(((value * multiplier + shift) % 26) + base);
  });
}

function railFenceEncode(text, rails) {
  const rows = Array.from({ length: rails }, () => []);
  let rail = 0;
  let direction = 1;
  for (const char of String(text || "")) {
    rows[rail].push(char);
    if (rail === 0) direction = 1;
    if (rail === rails - 1) direction = -1;
    rail += direction;
  }
  return rows.map((row) => row.join("")).join("");
}

function base91Encode(text) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\"";
  const bytes = Buffer.from(text, "utf8");
  let accumulator = 0;
  let bits = 0;
  let output = "";

  for (const byte of bytes) {
    accumulator |= byte << bits;
    bits += 8;
    if (bits > 13) {
      let value = accumulator & 8191;
      if (value > 88) {
        accumulator >>= 13;
        bits -= 13;
      } else {
        value = accumulator & 16383;
        accumulator >>= 14;
        bits -= 14;
      }
      output += alphabet[value % 91] + alphabet[Math.floor(value / 91)];
    }
  }

  if (bits) {
    output += alphabet[accumulator % 91];
    if (bits > 7 || accumulator > 90) {
      output += alphabet[Math.floor(accumulator / 91)];
    }
  }

  return output;
}

function z85Encode(text) {
  const alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";
  const buffer = Buffer.from(text, "utf8");
  if (buffer.length % 4 !== 0) {
    throw new Error("Z85 smoke fixture text length must be divisible by 4");
  }

  let output = "";
  for (let index = 0; index < buffer.length; index += 4) {
    let value = buffer.readUInt32BE(index);
    const encoded = new Array(5);
    for (let digit = 4; digit >= 0; digit -= 1) {
      encoded[digit] = alphabet[value % 85];
      value = Math.floor(value / 85);
    }
    output += encoded.join("");
  }
  return output;
}

function dna2BitEncode(text) {
  const alphabet = ["A", "C", "G", "T"];
  return Array.from(Buffer.from(text, "utf8"))
    .map((byte) => byte.toString(2).padStart(8, "0").match(/../g).map((bits) => alphabet[parseInt(bits, 2)]).join(""))
    .join("");
}

function a1z26Encode(text) {
  return String(text || "")
    .toUpperCase()
    .split("")
    .map((char) => (/[A-Z]/.test(char) ? String(char.charCodeAt(0) - 64) : char === "-" ? "/" : ""))
    .filter(Boolean)
    .join(" ");
}

function uuencodeText(text, fileName = "flag.txt") {
  const bytes = Buffer.from(text, "utf8");
  const lines = [`begin 644 ${fileName}`];
  for (let offset = 0; offset < bytes.length; offset += 45) {
    const chunk = bytes.subarray(offset, offset + 45);
    let line = String.fromCharCode((chunk.length & 0x3f) + 32);
    for (let index = 0; index < chunk.length; index += 3) {
      const block = Buffer.concat([chunk.subarray(index, index + 3), Buffer.alloc(Math.max(0, 3 - (chunk.length - index)))]);
      const values = [block[0] >> 2, ((block[0] & 0x03) << 4) | (block[1] >> 4), ((block[1] & 0x0f) << 2) | (block[2] >> 6), block[2] & 0x3f];
      line += values.map((value) => String.fromCharCode((value & 0x3f) + 32)).join("");
    }
    lines.push(line);
  }
  lines.push("`", "end");
  return `${lines.join("\n")}\n`;
}

async function main() {
  const root = path.resolve(__dirname, "..", "tmp", "smoke", String(Date.now()));
  resetDir(root);

  const results = [];
  const directFlag = "flag{direct_text_smoke}";
  const directTextPath = writeText(path.join(root, "input", "direct.txt"), `plain hit: ${directFlag}\n`);
  results.push(
    await runCase(
      root,
      "direct-text",
      {
        title: "direct text smoke",
        description: "Direct flag extraction from a text attachment.",
        artifacts: [directTextPath],
      },
      directFlag,
    ),
  );

  const pwnFlag = "flag{pwn_static_smoke}";
  const pwnElfPath = createPwnElf64(path.join(root, "input", "pwn-smoke.elf"), pwnFlag);
  results.push(await runPwnCase(root, pwnElfPath, pwnFlag));

  const zipCommentFlag = "flag{zip_comment_smoke}";
  const zipCommentPath = createZipWithComment(path.join(root, "input", "comment.zip"), zipCommentFlag);
  results.push(
    await runCase(
      root,
      "zip-comment",
      {
        title: "zip comment smoke",
        description: "ZIP global comments should be surfaced as generated clue reports.",
        artifacts: [zipCommentPath],
      },
      zipCommentFlag,
    ),
  );

  const pseudoZipFlag = "flag{pseudo_zip_smoke}";
  const pseudoZipPath = createPseudoEncryptedZip(path.join(root, "input", "pseudo.zip"), pseudoZipFlag);
  results.push(
    await runCase(
      root,
      "pseudo-encrypted-zip",
      {
        title: "pseudo encrypted zip smoke",
        description: "ZIP entries marked encrypted but not actually encrypted should be repaired locally.",
        artifacts: [pseudoZipPath],
      },
      pseudoZipFlag,
    ),
  );

  const tgzFlag = "flag{tgz_tar_recursive_smoke}";
  const tgzPath = createTgz(path.join(root, "input", "recursive.tgz"), tgzFlag);
  results.push(
    await runCase(
      root,
      "tgz-tar-recursive",
      {
        title: "tgz tar recursive smoke",
        description: "TGZ should inflate to TAR and recursively expose the flag file.",
        artifacts: [tgzPath],
      },
      tgzFlag,
    ),
  );

  const bmpFlag = "flag{bmp_lsb_smoke}";
  const bmpPath = createBmpLsb(path.join(root, "input", "hidden.bmp"), bmpFlag);
  results.push(
    await runCase(
      root,
      "bmp-lsb",
      {
        title: "bmp lsb smoke",
        description: "BMP blue-channel LSB should be decoded locally.",
        artifacts: [bmpPath],
      },
      bmpFlag,
    ),
  );

  const gifFlag = "flag{gif_comment_smoke}";
  const gifPath = createGifSplitComment(path.join(root, "input", "comment.gif"), ["flag{gif_", "comment_", "smoke}"]);
  results.push(
    await runCase(
      root,
      "gif-split-comment",
      {
        title: "gif split comment smoke",
        description: "GIF comment sub-blocks should be reassembled before flag scanning.",
        artifacts: [gifPath],
      },
      gifFlag,
    ),
  );

  const quotedPrintableFlag = "FLAG-QP-SMOKE";
  const quotedPrintablePath = writeText(path.join(root, "input", "quoted-printable.txt"), "=46=4C=41=47=2D=51=50=2D=53=4D=4F=4B=45\n");
  results.push(
    await runCase(
      root,
      "quoted-printable-text",
      {
        title: "quoted printable smoke",
        description: "Quoted-Printable byte escapes should decode locally.",
        artifacts: [quotedPrintablePath],
      },
      quotedPrintableFlag,
    ),
  );

  const uuencodeFlag = "FLAG-UUENCODE-SMOKE";
  const uuencodePath = writeText(path.join(root, "input", "uuencode.txt"), uuencodeText(uuencodeFlag));
  results.push(
    await runCase(
      root,
      "uuencode-text",
      {
        title: "uuencode smoke",
        description: "UUEncode blocks should decode locally.",
        artifacts: [uuencodePath],
      },
      uuencodeFlag,
    ),
  );

  const base91Flag = "FLAG-BASE91-SMOKE";
  const base91Path = writeText(path.join(root, "input", "base91.txt"), `${base91Encode(base91Flag)}\n`);
  results.push(
    await runCase(
      root,
      "base91-text",
      {
        title: "base91 smoke",
        description: "Base91 text should decode locally.",
        artifacts: [base91Path],
      },
      base91Flag,
    ),
  );

  const z85Flag = "FLAG-Z85-SMOKE12";
  const z85Path = writeText(path.join(root, "input", "z85.txt"), `${z85Encode(z85Flag)}\n`);
  results.push(
    await runCase(
      root,
      "z85-text",
      {
        title: "z85 smoke",
        description: "Z85 text should decode locally.",
        artifacts: [z85Path],
      },
      z85Flag,
    ),
  );

  const a1z26Flag = "FLAG-AZ-SMOKE";
  const a1z26Path = writeText(path.join(root, "input", "a1z26.txt"), `${a1z26Encode(a1z26Flag)}\n`);
  results.push(
    await runCase(
      root,
      "a1z26-text",
      {
        title: "a1z26 smoke",
        description: "A1Z26 number streams should decode locally.",
        artifacts: [a1z26Path],
      },
      a1z26Flag,
    ),
  );

  const natoFlag = "FLAG-NATO-SMOKE";
  const natoPath = writeText(
    path.join(root, "input", "nato.txt"),
    "foxtrot lima alpha golf dash november alpha tango oscar dash sierra mike oscar kilo echo\n",
  );
  results.push(
    await runCase(
      root,
      "nato-text",
      {
        title: "nato phonetic smoke",
        description: "NATO phonetic words should decode locally.",
        artifacts: [natoPath],
      },
      natoFlag,
    ),
  );

  const dnaFlag = "FLAG-DNA-SMOKE";
  const dnaPath = writeText(path.join(root, "input", "dna.txt"), `${dna2BitEncode(dnaFlag)}\n`);
  results.push(
    await runCase(
      root,
      "dna-2bit-text",
      {
        title: "dna two bit smoke",
        description: "DNA 2-bit nucleotide streams should decode locally.",
        artifacts: [dnaPath],
      },
      dnaFlag,
    ),
  );

  const affineFlag = "FLAG-AFFINE-SMOKE";
  const affinePath = writeText(path.join(root, "input", "affine.txt"), `${affineEncode(affineFlag, 5, 8)}\n`);
  results.push(
    await runCase(
      root,
      "affine-text",
      {
        title: "affine cipher smoke",
        description: "Small affine brute force should recover the flag candidate.",
        artifacts: [affinePath],
      },
      affineFlag,
    ),
  );

  const railFlag = "FLAG-RAIL-SMOKE";
  const railPath = writeText(path.join(root, "input", "rail.txt"), `${railFenceEncode(railFlag, 3)}\n`);
  results.push(
    await runCase(
      root,
      "rail-fence-text",
      {
        title: "rail fence smoke",
        description: "Rail fence brute force should recover the flag candidate.",
        artifacts: [railPath],
      },
      railFlag,
    ),
  );

  const morseFlag = "FLAG-MORSE-SMOKE";
  const morsePath = writeText(
    path.join(root, "input", "morse.txt"),
    "..-. .-.. .- --. -....- -- --- .-. ... . -....- ... -- --- -.- .\n",
  );
  results.push(
    await runCase(
      root,
      "morse-text",
      {
        title: "morse misc smoke",
        description: "Text Morse should be decoded locally without audio tooling.",
        artifacts: [morsePath],
      },
      morseFlag,
    ),
  );

  const polybiusFlag = "FLAG-POLYBIUS-SMOKE";
  const polybiusPath = writeText(path.join(root, "input", "polybius.txt"), "21 31 11 22 / 35 34 31 54 12 24 45 43 / 43 32 34 25 15\n");
  results.push(
    await runCase(
      root,
      "polybius-text",
      {
        title: "polybius misc smoke",
        description: "Polybius coordinates should be decoded locally.",
        artifacts: [polybiusPath],
      },
      polybiusFlag,
    ),
  );

  const ookFlag = "FLAG-OOK-SMOKE";
  const ookPath = writeText(path.join(root, "input", "ook.txt"), `${brainfuckToOok(createBrainfuckPrint(ookFlag))}\n`);
  results.push(
    await runCase(
      root,
      "ook-text",
      {
        title: "ook brainfuck dialect smoke",
        description: "Ook should normalize to Brainfuck and emit a flag candidate.",
        artifacts: [ookPath],
      },
      ookFlag,
    ),
  );

  const samplePath = path.resolve(process.env.CTF_COMPASS_SAMPLE || DEFAULT_SAMPLE);
  const expectedFlag = process.env.CTF_COMPASS_EXPECTED_FLAG || DEFAULT_EXPECTED_FLAG;
  if (fs.existsSync(samplePath)) {
    results.push(
      await runCase(
        root,
        "f5-recursive-sample",
        {
          title: "smoke F5 JPEG",
          description: "Regression sample for ZIP -> JPEG F5 -> pseudo-encrypted ZIP -> flag.txt.",
          notes: "password abc123",
          artifacts: [samplePath],
        },
        expectedFlag,
      ),
    );
  } else {
    results.push({
      name: "f5-recursive-sample",
      status: "skipped",
      reason: `sample not found at ${samplePath}`,
    });
  }

  console.log(JSON.stringify({ root, results }, null, 2));
}

main().catch((error) => {
  fail(error?.stack || error?.message || String(error));
});
