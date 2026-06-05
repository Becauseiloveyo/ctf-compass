const fs = require("fs");
const path = require("path");
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
