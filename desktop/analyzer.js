const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const zlib = require("zlib");
const AdmZip = require("adm-zip");
const Quagga = require("@ericblade/quagga2").default;
const ExifParser = require("exif-parser");
const jpeg = require("jpeg-js");
const jsQR = require("jsqr");
const { PNG } = require("pngjs");

const MAX_FILES = 160;
const MAX_SAMPLE_BYTES = 1024 * 1024;
const MAX_TEXT_BYTES = 512 * 1024;
const MAX_ARCHIVE_ENTRIES = 80;
const MAX_ARCHIVE_TOTAL_BYTES = 32 * 1024 * 1024;
const MAX_PIPELINE_DEPTH = 3;
const MAX_TRAFFIC_BYTES = 24 * 1024 * 1024;
const MAX_TRAFFIC_FRAMES = 12000;
const MAX_HTTP_OBJECTS = 24;
const MAX_HTTP_BODY_BYTES = 512 * 1024;
const MAX_AUDIO_BYTES = 12 * 1024 * 1024;
const MAX_AUDIO_SAMPLES = 600000;
const BARCODE_READERS = [
  "code_128_reader",
  "code_39_reader",
  "code_93_reader",
  "codabar_reader",
  "ean_reader",
  "ean_8_reader",
  "upc_reader",
  "upc_e_reader",
  "i2of5_reader",
  "2of5_reader",
];
const BARCODE_ATTEMPTS = [
  {
    inputStream: { size: 0 },
    locate: true,
    locator: { patchSize: "medium", halfSample: false },
    decoder: { readers: BARCODE_READERS },
  },
  {
    inputStream: { size: 0 },
    locate: false,
    decoder: { readers: BARCODE_READERS },
  },
  {
    inputStream: { size: 1200 },
    locate: true,
    locator: { patchSize: "large", halfSample: false },
    decoder: { readers: BARCODE_READERS },
  },
];

const EMBEDDED_SIGNATURES = [
  { id: "zip", label: "ZIP", ext: ".zip", magic: Buffer.from([0x50, 0x4b, 0x03, 0x04]) },
  { id: "gzip", label: "GZIP", ext: ".gz", magic: Buffer.from([0x1f, 0x8b]) },
  { id: "png", label: "PNG", ext: ".png", magic: Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) },
  { id: "pdf", label: "PDF", ext: ".pdf", magic: Buffer.from("%PDF") },
  { id: "elf", label: "ELF", ext: ".elf", magic: Buffer.from([0x7f, 0x45, 0x4c, 0x46]) },
  { id: "sevenzip", label: "7Z", ext: ".7z", magic: Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) },
  { id: "rar", label: "RAR", ext: ".rar", magic: Buffer.from([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07]) },
];

const COPY = {
  app: {
    unnamed: "\u672a\u547d\u540d\u9898\u76ee",
    noFlags: "\u6682\u672a\u53d1\u73b0\u76f4\u63a5 flag\uff0c\u4f18\u5148\u68c0\u67e5\u9644\u4ef6\u7ec6\u8282\u3001\u7f16\u7801\u53d8\u6362\u548c\u6d41\u91cf\u4f1a\u8bdd\u3002",
    truncated: `\u4e3a\u4fdd\u8bc1\u901f\u5ea6\uff0c\u672c\u6b21\u6700\u591a\u89e3\u6790 ${MAX_FILES} \u4e2a\u6587\u4ef6\u3002`,
  },
  categories: {
    crypto: "\u5bc6\u7801",
    web: "Web",
    reverse: "\u9006\u5411",
    pwn: "Pwn",
    forensic: "\u53d6\u8bc1",
    misc: "\u6742\u9879",
  },
  families: {
    text: "\u6587\u672c",
    image: "\u56fe\u50cf",
    audio: "\u97f3\u9891",
    network: "\u6d41\u91cf",
    archive: "\u538b\u7f29\u5305",
    binary: "\u4e8c\u8fdb\u5236",
    document: "\u6587\u6863",
    unknown: "\u5176\u4ed6",
  },
  summary: {
    crypto: "\u5148\u5904\u7406\u7f16\u7801\u3001\u6570\u5b66\u5173\u7cfb\u548c\u53c2\u6570\u590d\u7528\u95ee\u9898\uff0c\u518d\u5224\u65ad\u662f\u5426\u8fdb\u5165\u5bc6\u7801\u5206\u6790\u3002",
    web: "\u5148\u68b3\u7406\u8def\u7531\u3001\u8bf7\u6c42\u3001Cookie\u3001\u4e0a\u4f20\u70b9\u548c\u4f1a\u8bdd\u8fb9\u754c\uff0c\u518d\u9501\u5b9a\u6f0f\u6d1e\u7c7b\u578b\u3002",
    reverse: "\u4ece strings\u3001\u5bfc\u5165\u8868\u3001\u67b6\u6784\u548c\u6821\u9a8c\u6d41\u7a0b\u5165\u624b\uff0c\u5148\u6062\u590d\u7a0b\u5e8f\u903b\u8f91\u518d\u5904\u7406 flag \u8def\u5f84\u3002",
    pwn: "\u5148\u5224\u65ad\u4e8c\u8fdb\u5236\u4fdd\u62a4\u3001I/O \u6a21\u5f0f\u548c\u5185\u5b58\u539f\u8bed\uff0c\u4e0d\u8981\u5728\u6ca1\u5b9a\u6027\u524d\u76f2\u731c\u5229\u7528\u94fe\u3002",
    forensic: "\u5148\u4fdd\u5168\u8bc1\u636e\uff0c\u68b3\u7406\u9644\u4ef6\u548c\u6d41\u91cf\u75d5\u8ff9\uff0c\u91cd\u70b9\u770b\u9690\u85cf\u6570\u636e\u3001\u5d4c\u5957\u6587\u4ef6\u548c\u4ea4\u4e92\u8bb0\u5f55\u3002",
    misc: "\u9898\u76ee\u53ef\u80fd\u6d89\u53ca\u56fe\u50cf\u9690\u5199\u3001\u7f16\u7801\u53d8\u6362\u3001\u6587\u4ef6\u9690\u85cf\u6216\u534f\u8bae\u7ec4\u88c5\uff0c\u5148\u505a\u7c7b\u578b\u7f29\u7a84\u3002",
  },
  nextMoves: {
    crypto: [
      "\u5148\u628a\u9644\u4ef6\u91cc\u53ef\u89c1\u7684\u5b57\u7b26\u4e32\u3001base64\u3001hex \u548c\u6570\u5b66\u5e38\u91cf\u62bd\u51fa\u6765\u3002",
      "\u68c0\u67e5\u662f\u5426\u6709 XOR\u3001RSA\u3001\u91cd\u590d nonce\u3001padding \u5f02\u5e38\u6216\u5bc6\u6587\u5206\u5757\u7279\u5f81\u3002",
      "\u5982\u679c\u9644\u4ef6\u662f txt\u3001log \u6216 payload\uff0c\u5148\u628a\u7f16\u7801\u5c42\u8fd8\u539f\u518d\u8003\u8651\u5bc6\u7801\u5c42\u3002",
    ],
    web: [
      "\u7528\u9644\u4ef6\u548c\u9898\u9762\u68b3\u7406 URL\u3001Cookie\u3001Token\u3001\u4e0a\u4f20\u70b9\u548c\u8fd4\u56de\u5f02\u5e38\u4fe1\u606f\u3002",
      "\u5982\u679c\u6709 pcap \u6216 HTTP \u65e5\u5fd7\uff0c\u5148\u91cd\u5efa\u4f1a\u8bdd\u3001\u53c2\u6570\u548c\u6587\u4ef6\u4f20\u8f93\u8def\u5f84\u3002",
      "\u4f18\u5148\u5224\u65ad\u662f auth\u3001template\u3001upload\u3001deserialize \u8fd8\u662f SSRF \u65b9\u5411\u3002",
    ],
    reverse: [
      "\u5148\u770b strings \u548c\u5bfc\u5165\u51fd\u6570\uff0c\u786e\u8ba4\u7a0b\u5e8f\u662f\u5426\u5b58\u5728\u660e\u663e\u7684\u6821\u9a8c\u548c\u89e3\u7801\u903b\u8f91\u3002",
      "\u5bf9 ELF\u3001PE\u3001APK \u5206\u522b\u505a\u67b6\u6784\u548c\u884c\u4e3a\u5206\u6d41\uff0c\u4f18\u5148\u8ddf\u8fdb flag \u751f\u6210\u8def\u5f84\u3002",
      "\u5982\u679c strings \u91cc\u6709 flag \u7247\u6bb5\u3001key\u3001check \u7b49\u63d0\u793a\uff0c\u76f4\u63a5\u56de\u5230\u76f8\u5e94\u51fd\u6570\u3002",
    ],
    pwn: [
      "\u68c0\u67e5 ELF \u548c libc \u7ebf\u7d22\uff0c\u786e\u8ba4\u4fdd\u62a4\u9879\u540e\u518d\u9009\u62e9 ret2libc\u3001ROP \u6216 heap \u65b9\u5411\u3002",
      "\u5148\u627e\u8f93\u5165\u70b9\u3001\u5d29\u6e83\u70b9\u548c\u63a7\u5236\u6d41\u6539\u5199\u53ef\u80fd\u6027\uff0c\u4e0d\u8981\u76f4\u63a5\u731c\u5229\u7528\u94fe\u3002",
      "\u5982\u679c\u9644\u4ef6\u91cc\u6709 core\u3001log \u6216 pcap\uff0c\u628a\u8f93\u5165\u6d41\u7a0b\u4e0e\u5185\u5b58\u5f02\u5e38\u5bf9\u5e94\u8d77\u6765\u3002",
    ],
    forensic: [
      "\u4f18\u5148\u6309\u9644\u4ef6\u7c7b\u578b\u5206\u7ec4\uff1a\u56fe\u50cf\u3001\u6587\u672c\u3001\u6d41\u91cf\u5305\u3001\u538b\u7f29\u5305\u3001\u4e8c\u8fdb\u5236\u3002",
      "\u5bf9 pcap/pcapng \u5148\u770b HTTP\u3001DNS\u3001TLS \u63e1\u624b\u3001\u5bfc\u51fa\u5bf9\u8c61\u548c cookie/token\u3002",
      "\u5bf9\u56fe\u50cf\u548c\u538b\u7f29\u5305\u5148\u67e5\u770b\u9690\u85cf\u6587\u4ef6\u3001\u989d\u5916\u5c3e\u90e8\u6570\u636e\u548c\u5143\u6570\u636e\u3002",
    ],
    misc: [
      "\u5148\u7528\u9644\u4ef6\u63d0\u793a\u7f29\u5c0f\u9898\u578b\uff0c\u4e0d\u8981\u53ea\u9760\u6807\u9898\u548c\u63cf\u8ff0\u3002",
      "\u56fe\u50cf\u8d70\u9690\u5199\u3001\u6587\u672c\u8d70\u7f16\u7801/\u52a0\u5bc6\u3001pcap \u8d70\u6d41\u91cf\u8fd8\u539f\uff0c\u538b\u7f29\u5305\u8d70\u5d4c\u5957\u6587\u4ef6\u5206\u6790\u3002",
      "\u672a\u627e\u5230\u76f4\u63a5 flag \u65f6\uff0c\u4ece\u6700\u6709\u4fe1\u606f\u91cf\u7684\u9644\u4ef6\u5f00\u59cb\u5012\u63a8\u3002",
    ],
  },
  tools: {
    crypto: ["CyberChef", "SageMath", "Python \u7b14\u8bb0\u672c"],
    web: ["Burp Suite", "\u6d4f\u89c8\u5668\u5f00\u53d1\u8005\u5de5\u5177", "ffuf / dirsearch"],
    reverse: ["Ghidra", "IDA Free", "strings", "binwalk"],
    pwn: ["pwndbg", "checksec", "GDB", "ROPgadget"],
    forensic: ["Wireshark", "Autopsy", "binwalk", "exiftool"],
    misc: ["CyberChef", "binwalk", "zsteg", "Wireshark"],
  },
  needs: [
    "\u6587\u4ef6\u4f18\u5148\u5de5\u4f5c\u6d41\uff1a\u9898\u76ee\u4e0d\u5e94\u53ea\u6709\u6807\u9898\u548c\u63cf\u8ff0\uff0c\u9644\u4ef6\u5e94\u8be5\u662f\u4e00\u7b49\u8f93\u5165\u3002",
    "\u9644\u4ef6\u5206\u578b\u89e3\u6790\uff1a\u56fe\u50cf\u3001\u6587\u672c\u3001\u538b\u7f29\u5305\u3001ELF\u3001pcap \u9700\u8981\u4e0d\u540c\u5206\u6790\u8def\u5f84\u3002",
    "flag \u5019\u9009\u63d0\u53d6\uff1a\u8981\u80fd\u4ece strings\u3001base64\u3001hex\u3001http \u8f7d\u8377\u4e2d\u81ea\u52a8\u62bd\u53d6\u53ef\u80fd\u503c\u3002",
    "\u6d41\u91cf\u5de5\u4f5c\u53f0\uff1a\u9700\u8981\u7ed9 pcap/pcapng \u5355\u72ec\u7684\u4f1a\u8bdd\u3001HTTP\u3001DNS\u3001\u5bfc\u51fa\u5bf9\u8c61\u89c6\u89d2\u3002",
    "\u8bc1\u636e\u8bb0\u5f55\uff1a\u5bf9\u6bcf\u4e2a\u9644\u4ef6\u8bb0\u5f55\u53ef\u7591\u70b9\u3001\u5019\u9009 flag \u548c\u4eba\u5de5\u7ed3\u8bba\u3002",
    "\u79bb\u7ebf\u53ef\u5206\u53d1\uff1a\u6253\u5305\u540e\u4e0d\u5e94\u4f9d\u8d56\u5916\u90e8 Python \u6216\u989d\u5916\u73af\u5883\u3002",
  ],
};

const CATEGORY_RULES = {
  crypto: ["rsa", "aes", "xor", "cipher", "nonce", "modulus", "prime", "decrypt", "encrypt", "base64", "hex"],
  web: ["http", "https", "cookie", "session", "jwt", "request", "route", "upload", "template", "csrf", "xss", "sql", "login"],
  reverse: ["binary", "elf", "pe32", "exe", "dll", "ghidra", "ida", "strings", "disasm", "symbol", "apk", "java"],
  pwn: ["overflow", "heap", "rop", "libc", "canary", "format string", "uaf", "fastbin", "tcache", "stack smashing"],
  forensic: ["pcap", "pcapng", "traffic", "dns", "http", "memory", "disk", "metadata", "artifact", "timeline", "capture"],
  misc: ["stego", "steganography", "puzzle", "logic", "encoding", "qr", "audio", "image", "hidden", "zip"],
};

const KNOWN_FLAG_PREFIX = /\b(?:flag|ctf|key|answer|picoCTF|moectf|actf|hitcon|sekai|balsn|uiuctf|n1ctf)\{/i;
const NATURAL_TEXT_HINT = /\b(?:the|this|that|flag|password|secret|cookie|session|token|login|http|https|user|admin|hello|world|image|file|data|text)\b/i;
const OFFICE_DOCUMENT_EXTENSIONS = [".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".odt", ".ods", ".odp"];

function formatBytes(size) {
  if (size < 1024) {
    return `${size} B`;
  }
  if (size < 1024 * 1024) {
    return `${(size / 1024).toFixed(1)} KB`;
  }
  if (size < 1024 * 1024 * 1024) {
    return `${(size / (1024 * 1024)).toFixed(1)} MB`;
  }
  return `${(size / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

function dedupeStrings(values) {
  return Array.from(new Set(values.filter(Boolean)));
}

function sanitizeSegment(value) {
  return String(value || "")
    .replace(/[<>:"/\\|?*\x00-\x1f]/g, "_")
    .replace(/\s+/g, "-")
    .slice(0, 80);
}

function shortHash(value) {
  return crypto.createHash("sha1").update(String(value)).digest("hex").slice(0, 8);
}

function safeArchivePath(entryName) {
  return entryName
    .split(/[\\/]+/)
    .filter(Boolean)
    .map((segment) => sanitizeSegment(segment) || "_")
    .join(path.sep);
}

function extractPrintableSegments(text, minLength = 8, maxCount = 20) {
  return dedupeStrings(
    Array.from(text.matchAll(new RegExp(`[\\x20-\\x7E]{${minLength},}`, "g")))
      .map((match) => match[0].trim())
      .filter((value) => value.length >= minLength)
      .slice(0, maxCount),
  );
}

function base32Decode(value) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  const cleaned = value.toUpperCase().replace(/=+$/g, "");
  for (const char of cleaned) {
    const index = alphabet.indexOf(char);
    if (index === -1) {
      throw new Error("Invalid base32");
    }
    bits += index.toString(2).padStart(5, "0");
  }

  const bytes = [];
  for (let offset = 0; offset + 8 <= bits.length; offset += 8) {
    bytes.push(parseInt(bits.slice(offset, offset + 8), 2));
  }
  return Buffer.from(bytes);
}

function ascii85Decode(value) {
  const cleaned = String(value || "")
    .replace(/^<~/, "")
    .replace(/~>$/, "")
    .replace(/\s+/g, "");

  if (!cleaned) {
    return Buffer.alloc(0);
  }

  const bytes = [];
  let block = [];

  for (const char of cleaned) {
    if (char === "z" && !block.length) {
      bytes.push(0, 0, 0, 0);
      continue;
    }

    const code = char.charCodeAt(0);
    if (code < 33 || code > 117) {
      throw new Error("Invalid ascii85");
    }

    block.push(code - 33);
    if (block.length === 5) {
      let value32 = 0;
      block.forEach((item) => {
        value32 = value32 * 85 + item;
      });
      bytes.push((value32 >>> 24) & 0xff, (value32 >>> 16) & 0xff, (value32 >>> 8) & 0xff, value32 & 0xff);
      block = [];
    }
  }

  if (block.length) {
    const originalLength = block.length;
    while (block.length < 5) {
      block.push(84);
    }
    let value32 = 0;
    block.forEach((item) => {
      value32 = value32 * 85 + item;
    });
    const tail = [(value32 >>> 24) & 0xff, (value32 >>> 16) & 0xff, (value32 >>> 8) & 0xff, value32 & 0xff];
    bytes.push(...tail.slice(0, originalLength - 1));
  }

  return Buffer.from(bytes);
}

function extractUnicodeStrings(buffer, minLength = 4, maxCount = 3000) {
  const matches = [];

  for (const start of [0, 1]) {
    let current = [];
    for (let index = start; index + 1 < buffer.length; index += 2) {
      const code = buffer.readUInt16LE(index);
      const isPrintable = code === 9 || code === 10 || code === 13 || (code >= 32 && code <= 126);
      if (isPrintable) {
        current.push(String.fromCharCode(code));
        continue;
      }
      if (current.length >= minLength) {
        matches.push(current.join(""));
        if (matches.length >= maxCount) {
          return dedupeStrings(matches);
        }
      }
      current = [];
    }

    if (current.length >= minLength && matches.length < maxCount) {
      matches.push(current.join(""));
    }
  }

  return dedupeStrings(matches).slice(0, maxCount);
}

function scoreDecodedText(text) {
  if (!text) {
    return 0;
  }
  const printable = (text.match(/[\x20-\x7e]/g) || []).length / text.length;
  const spaces = (text.match(/\s/g) || []).length;
  const common = (text.match(/[etaoinshrdlu]/gi) || []).length;
  const flagBonus = /flag\{|ctf\{|key\{/i.test(text) ? 12 : 0;
  const asciiPenalty = (text.match(/[^\x09\x0a\x0d\x20-\x7e]/g) || []).length * 0.5;
  return printable * 6 + spaces * 0.08 + common * 0.04 + flagBonus - asciiPenalty;
}

function trySingleByteXor(buffer) {
  const results = [];
  for (let key = 1; key < 256; key += 1) {
    const decodedBuffer = Buffer.alloc(buffer.length);
    for (let index = 0; index < buffer.length; index += 1) {
      decodedBuffer[index] = buffer[index] ^ key;
    }
    const text = decodeBufferAsText(decodedBuffer).trim();
    if (!text || text.length < 6) {
      continue;
    }
    const score = scoreDecodedText(text);
    if (score < 5) {
      continue;
    }
    results.push({
      type: "xor",
      key,
      value: text.slice(0, 240),
      score,
    });
  }

  return results.sort((left, right) => right.score - left.score).slice(0, 5);
}

function caesarShift(text, shift) {
  return text.replace(/[A-Za-z]/g, (char) => {
    const code = char.charCodeAt(0);
    const base = code >= 97 ? 97 : 65;
    return String.fromCharCode(((code - base + shift + 26) % 26) + base);
  });
}

function tryInflateVariants(buffer) {
  if (!buffer || buffer.length < 6 || buffer.length > 128 * 1024) {
    return [];
  }

  const variants = [];
  const attempts = [
    { type: "gunzip", label: "GUNZIP", run: () => zlib.gunzipSync(buffer, { maxOutputLength: MAX_TEXT_BYTES }) },
    { type: "inflate", label: "INFLATE", run: () => zlib.inflateSync(buffer, { maxOutputLength: MAX_TEXT_BYTES }) },
    { type: "inflate-raw", label: "INFLATE-RAW", run: () => zlib.inflateRawSync(buffer, { maxOutputLength: MAX_TEXT_BYTES }) },
  ];

  attempts.forEach((attempt) => {
    try {
      const inflated = attempt.run();
      if (inflated && inflated.length && inflated.length <= MAX_TEXT_BYTES) {
        variants.push({
          type: attempt.type,
          label: attempt.label,
          buffer: inflated,
        });
      }
    } catch (_error) {
      // ignore unsupported streams
    }
  });

  const deduped = new Map();
  variants.forEach((item) => {
    deduped.set(item.buffer.toString("base64"), item);
  });
  return Array.from(deduped.values());
}

function pushDecodedResult(bucket, item) {
  const value = String(item.value || "").trim();
  if (!value || value.length < 4) {
    return;
  }

  const score = typeof item.score === "number" ? item.score : scoreDecodedText(value);
  const strict = Boolean(item.strict);
  const looksLikeFlag = KNOWN_FLAG_PREFIX.test(value) || /\bflag[:=_ -]{0,4}[a-zA-Z0-9_\/+=-]{6,160}\b/i.test(value);
  const looksLikeNaturalText = NATURAL_TEXT_HINT.test(value) || /\s/.test(value);

  if (strict && !looksLikeFlag && (!looksLikeNaturalText || score < 8)) {
    return;
  }
  if (score < 4 && !/flag\{|ctf\{|key\{/i.test(value)) {
    return;
  }

  bucket.push({
    type: item.type,
    label: item.label,
    value: value.slice(0, 240),
    score,
  });
}

function collectTextVariantsFromBuffer(buffer, label, bucket) {
  const decoded = decodeBufferAsText(buffer).trim();
  pushDecodedResult(bucket, {
    type: label.toLowerCase(),
    label,
    value: decoded,
  });

  if (buffer.length <= 2048) {
    trySingleByteXor(buffer).forEach((item) => {
      pushDecodedResult(bucket, {
        type: "xor",
        label: `${label} -> XOR 0x${item.key.toString(16).padStart(2, "0")}`,
        value: item.value,
        score: item.score,
        strict: true,
      });
    });
  }

  tryInflateVariants(buffer).forEach((variant) => {
    pushDecodedResult(bucket, {
      type: variant.type,
      label: `${label} -> ${variant.label}`,
      value: decodeBufferAsText(variant.buffer),
    });

    if (variant.buffer.length <= 2048) {
      trySingleByteXor(variant.buffer).forEach((item) => {
        pushDecodedResult(bucket, {
          type: "xor",
          label: `${label} -> ${variant.label} -> XOR 0x${item.key.toString(16).padStart(2, "0")}`,
          value: item.value,
          score: item.score,
          strict: true,
        });
      });
    }
  });
}

function smartDecodeTextContent(buffer) {
  const text = decodeBufferAsText(buffer);
  const encoded = findEncodedSegments(text);
  const results = [];
  const directFlagHits = findFlagCandidates(text, "inline").length;
  const wholeTextTransformAllowed =
    buffer.length <= 4096 &&
    directFlagHits === 0 &&
    !NATURAL_TEXT_HINT.test(text) &&
    ((text.match(/\s/g) || []).length <= Math.max(2, text.length * 0.06));

  encoded.base64.forEach((value) => {
    try {
      collectTextVariantsFromBuffer(Buffer.from(value, "base64"), "BASE64", results);
    } catch (_error) {
      // ignore
    }
  });

  encoded.hex.forEach((value) => {
    try {
      collectTextVariantsFromBuffer(Buffer.from(value, "hex"), "HEX", results);
    } catch (_error) {
      // ignore
    }
  });

  const base32Matches = dedupeStrings(
    Array.from(text.matchAll(/(?:^|[^A-Z2-7])([A-Z2-7]{16,}={0,6})(?=$|[^A-Z2-7=])/g)).map((match) => match[1]).slice(0, 12),
  );
  base32Matches.forEach((value) => {
    try {
      collectTextVariantsFromBuffer(base32Decode(value), "BASE32", results);
    } catch (_error) {
      // ignore
    }
  });

  const ascii85Matches = dedupeStrings(Array.from(text.matchAll(/<~[\s\S]{10,}?~>/g)).map((match) => match[0]).slice(0, 8));
  ascii85Matches.forEach((value) => {
    try {
      collectTextVariantsFromBuffer(ascii85Decode(value), "ASCII85", results);
    } catch (_error) {
      // ignore
    }
  });

  const urlMatches = dedupeStrings(Array.from(text.matchAll(/(?:%[0-9a-fA-F]{2}){4,}/g)).map((match) => match[0]).slice(0, 12));
  urlMatches.forEach((value) => {
    try {
      collectTextVariantsFromBuffer(Buffer.from(decodeURIComponent(value), "utf8"), "URL", results);
    } catch (_error) {
      // ignore
    }
  });

  if (wholeTextTransformAllowed) {
    const rot13 = caesarShift(text, 13);
    pushDecodedResult(results, {
      type: "rot13",
      label: "ROT13",
      value: rot13,
      strict: true,
    });

    const caesarResults = [];
    for (let shift = 1; shift < 26; shift += 1) {
      const shifted = caesarShift(text, shift);
      pushDecodedResult(caesarResults, {
        type: "caesar",
        label: `CAESAR +${shift}`,
        value: shifted,
        score: scoreDecodedText(shifted) - (shift === 13 ? 0.5 : 0),
        strict: true,
      });
    }
    caesarResults
      .sort((left, right) => (right.score || 0) - (left.score || 0))
      .slice(0, 4)
      .forEach((item) => results.push(item));
  }

  if (buffer.length <= 2048 && wholeTextTransformAllowed) {
    trySingleByteXor(buffer).forEach((item) => {
      pushDecodedResult(results, {
        type: "xor",
        label: `XOR 0x${item.key.toString(16).padStart(2, "0")}`,
        value: item.value,
        score: item.score,
        strict: true,
      });
    });
  }

  const deduped = new Map();
  results.forEach((item) => {
    const key = `${item.type}@@${item.label}@@${item.value}`;
    const current = deduped.get(key);
    if (!current || (item.score || 0) > (current.score || 0)) {
      deduped.set(key, item);
    }
  });

  return Array.from(deduped.values())
    .sort((left, right) => (right.score || 0) - (left.score || 0))
    .slice(0, 20)
    .map(({ type, label, value }) => ({ type, label, value }));
}

function detectEmbeddedPayloads(buffer, offset = 128) {
  const hits = [];
  for (const signature of EMBEDDED_SIGNATURES) {
    const index = markerAfterOffset(buffer, signature.magic, offset);
    if (index !== -1) {
      hits.push({
        ...signature,
        offset: index,
      });
    }
  }

  return hits
    .sort((left, right) => left.offset - right.offset)
    .filter((item, index, array) => index === 0 || item.offset !== array[index - 1].offset || item.id !== array[index - 1].id);
}

function normalizeText(value) {
  return String(value || "").toLowerCase();
}

function isLikelyTextExtension(extension) {
  return [
    ".txt",
    ".md",
    ".log",
    ".csv",
    ".json",
    ".yaml",
    ".yml",
    ".xml",
    ".html",
    ".htm",
    ".js",
    ".ts",
    ".py",
    ".php",
    ".java",
    ".c",
    ".cpp",
    ".go",
    ".rs",
    ".sh",
    ".ps1",
    ".ini",
    ".cfg",
    ".conf",
  ].includes(extension);
}

function isOfficePackageExtension(extension) {
  return OFFICE_DOCUMENT_EXTENSIONS.includes(extension);
}

function detectMagic(buffer) {
  if (
    buffer.length >= 12 &&
    buffer.subarray(0, 4).toString("ascii") === "RIFF" &&
    buffer.subarray(8, 12).toString("ascii") === "WAVE"
  ) {
    return "wav";
  }
  if (buffer.length >= 8 && buffer.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) {
    return "png";
  }
  if (buffer.length >= 3 && buffer.subarray(0, 3).equals(Buffer.from([0xff, 0xd8, 0xff]))) {
    return "jpeg";
  }
  if (buffer.length >= 6 && buffer.subarray(0, 6).toString("ascii") === "GIF89a") {
    return "gif";
  }
  if (buffer.length >= 4 && (buffer.readUInt32LE(0) === 0xa1b2c3d4 || buffer.readUInt32LE(0) === 0xd4c3b2a1)) {
    return "pcap";
  }
  if (buffer.length >= 4 && buffer.readUInt32BE(0) === 0x0a0d0d0a) {
    return "pcapng";
  }
  if (buffer.length >= 4 && buffer.subarray(0, 4).equals(Buffer.from([0x50, 0x4b, 0x03, 0x04]))) {
    return "zip";
  }
  if (buffer.length >= 4 && buffer.subarray(0, 4).toString("ascii") === "\u007fELF") {
    return "elf";
  }
  if (buffer.length >= 2 && buffer.subarray(0, 2).toString("ascii") === "MZ") {
    return "pe";
  }
  if (buffer.length >= 4 && buffer.subarray(0, 4).toString("ascii") === "%PDF") {
    return "pdf";
  }
  if (buffer.length >= 2 && buffer[0] === 0x1f && buffer[1] === 0x8b) {
    return "gzip";
  }
  return "";
}

function extractAsciiStrings(buffer, minLength = 4, maxCount = 3000) {
  const matches = [];
  let current = [];

  for (const byte of buffer) {
    const isPrintable = byte >= 32 && byte <= 126;
    if (isPrintable) {
      current.push(String.fromCharCode(byte));
      continue;
    }
    if (current.length >= minLength) {
      matches.push(current.join(""));
      if (matches.length >= maxCount) {
        break;
      }
    }
    current = [];
  }

  if (current.length >= minLength && matches.length < maxCount) {
    matches.push(current.join(""));
  }

  return matches;
}

function decodeBufferAsText(buffer) {
  let text = buffer.toString("utf8").replace(/\0/g, "");
  const replacementCount = (text.match(/\uFFFD/g) || []).length;
  if (replacementCount > text.length * 0.02) {
    text = buffer.toString("latin1").replace(/\0/g, "");
  }
  return text;
}

function readSample(filePath, maxBytes) {
  const stat = fs.statSync(filePath);
  const length = Math.min(stat.size, maxBytes);
  const buffer = Buffer.alloc(length);
  const fd = fs.openSync(filePath, "r");
  fs.readSync(fd, buffer, 0, length, 0);
  fs.closeSync(fd);
  return { stat, buffer };
}

function scorePrintableRatio(buffer) {
  if (!buffer.length) {
    return 0;
  }
  let printable = 0;
  for (const byte of buffer) {
    if (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126)) {
      printable += 1;
    }
  }
  return printable / buffer.length;
}

function detectFamily(filePath, sample) {
  const extension = path.extname(filePath).toLowerCase();
  const magic = detectMagic(sample);

  if (magic === "pdf" || isOfficePackageExtension(extension) || [".doc", ".xls", ".ppt"].includes(extension)) {
    return { family: "document", badge: magic === "pdf" ? "PDF" : extension.slice(1).toUpperCase() || "DOC" };
  }
  if (["png", "jpeg", "gif"].includes(magic) || [".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg"].includes(extension)) {
    return { family: "image", badge: magic ? magic.toUpperCase() : extension.slice(1).toUpperCase() || "IMG" };
  }
  if (magic === "wav" || [".wav", ".mp3", ".flac", ".ogg", ".m4a"].includes(extension)) {
    return { family: "audio", badge: magic ? magic.toUpperCase() : extension.slice(1).toUpperCase() || "AUDIO" };
  }
  if (["pcap", "pcapng"].includes(magic) || [".pcap", ".pcapng", ".cap"].includes(extension)) {
    return { family: "network", badge: magic.toUpperCase() || extension.slice(1).toUpperCase() || "PCAP" };
  }
  if (["zip", "gzip"].includes(magic) || [".zip", ".7z", ".rar", ".tar", ".gz", ".tgz"].includes(extension)) {
    return { family: "archive", badge: magic.toUpperCase() || extension.slice(1).toUpperCase() || "ZIP" };
  }
  if (["elf", "pe"].includes(magic) || [".exe", ".dll", ".bin", ".so", ".elf", ".apk", ".jar"].includes(extension)) {
    return { family: "binary", badge: magic.toUpperCase() || extension.slice(1).toUpperCase() || "BIN" };
  }
  if (isLikelyTextExtension(extension) || scorePrintableRatio(sample) > 0.88) {
    return { family: "text", badge: extension.slice(1).toUpperCase() || "TXT" };
  }
  return { family: "unknown", badge: extension.slice(1).toUpperCase() || "FILE" };
}

function findFlagCandidates(text, source) {
  const candidates = [];
  const patterns = [
    /\b(?:flag|ctf|key|answer|picoCTF|moectf|actf|hitcon|sekai|balsn|uiuctf|n1ctf)\{[^{}\r\n]{3,160}\}/gi,
    /\b[a-zA-Z0-9_]{2,32}\{[^{}\r\n]{3,160}\}/g,
    /\bflag[:=_ -]{0,4}[a-zA-Z0-9_\/+=-]{6,160}\b/gi,
  ];

  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      candidates.push({
        value: match[0],
        source,
      });
    }
  }

  return candidates;
}

function findEncodedSegments(text) {
  const base64 = dedupeStrings(
    Array.from(text.matchAll(/(?:^|[^A-Za-z0-9+/])([A-Za-z0-9+/]{12,}={0,2})(?=$|[^A-Za-z0-9+/=])/g))
      .map((match) => match[1])
      .filter((value) => value.length % 4 === 0)
      .slice(0, 12),
  );

  const hex = dedupeStrings(
    Array.from(text.matchAll(/(?:^|[^0-9a-fA-F])(((?:[0-9a-fA-F]{2}){10,}))(?=$|[^0-9a-fA-F])/g))
      .map((match) => match[1])
      .slice(0, 12),
  );

  return { base64, hex };
}

function decodeInterestingSegments(encoded) {
  const findings = [];

  for (const value of encoded.base64) {
    try {
      const decoded = Buffer.from(value, "base64").toString("utf8");
      if (!decoded || decoded.length < 4) {
        continue;
      }
      if ((decoded.match(/[\uFFFD]/g) || []).length > decoded.length * 0.1) {
        continue;
      }
      findings.push({
        type: "base64",
        value: decoded.slice(0, 180),
      });
    } catch (_error) {
      // ignore
    }
  }

  for (const value of encoded.hex) {
    try {
      const decoded = Buffer.from(value, "hex").toString("utf8");
      if (!decoded || decoded.length < 4) {
        continue;
      }
      findings.push({
        type: "hex",
        value: decoded.slice(0, 180),
      });
    } catch (_error) {
      // ignore
    }
  }

  return findings;
}

function readPngDimensions(buffer) {
  if (detectMagic(buffer) !== "png" || buffer.length < 24) {
    return null;
  }
  return {
    width: buffer.readUInt32BE(16),
    height: buffer.readUInt32BE(20),
  };
}

function decodeImageRaster(buffer) {
  const magic = detectMagic(buffer);
  if (magic === "png") {
    const parsed = PNG.sync.read(buffer, { checkCRC: false });
    return {
      format: "png",
      width: parsed.width,
      height: parsed.height,
      data: parsed.data,
    };
  }
  if (magic === "jpeg") {
    const parsed = jpeg.decode(buffer, { useTArray: true, formatAsRGBA: true, tolerantDecoding: true });
    return {
      format: "jpeg",
      width: parsed.width,
      height: parsed.height,
      data: Buffer.from(parsed.data),
    };
  }
  return null;
}

function detectQrPayload(buffer) {
  let raster;
  try {
    raster = decodeImageRaster(buffer);
  } catch (_error) {
    return null;
  }

  if (!raster || !raster.width || !raster.height) {
    return null;
  }

  try {
    const code = jsQR(new Uint8ClampedArray(raster.data), raster.width, raster.height, {
      inversionAttempts: "attemptBoth",
    });
    return code && code.data ? code.data.trim() : null;
  } catch (_error) {
    return null;
  }
}

function decodeSingleBarcode(filePath, config) {
  return new Promise((resolve) => {
    try {
      Quagga.decodeSingle(
        {
          src: filePath,
          ...config,
        },
        (result) => {
          const value = result?.codeResult?.code;
          resolve(value ? String(value).trim() : null);
        },
      );
    } catch (_error) {
      resolve(null);
    }
  });
}

async function detectBarcodePayload(filePath) {
  if (!filePath || !fs.existsSync(filePath)) {
    return null;
  }

  for (const attempt of BARCODE_ATTEMPTS) {
    const value = await decodeSingleBarcode(filePath, attempt);
    if (value) {
      return value;
    }
  }

  return null;
}

function makeGrayPng(width, height, pixelSelector) {
  const png = new PNG({ width, height });
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) {
      const pixelOffset = (y * width + x) * 4;
      const value = Math.max(0, Math.min(255, pixelSelector(pixelOffset)));
      png.data[pixelOffset] = value;
      png.data[pixelOffset + 1] = value;
      png.data[pixelOffset + 2] = value;
      png.data[pixelOffset + 3] = 255;
    }
  }
  return PNG.sync.write(png);
}

function parseWavBuffer(buffer) {
  if (detectMagic(buffer) !== "wav" || buffer.length < 44) {
    return null;
  }

  const info = {
    audioFormat: 0,
    channels: 0,
    sampleRate: 0,
    byteRate: 0,
    blockAlign: 0,
    bitsPerSample: 0,
    durationSeconds: 0,
    metadata: {},
    chunks: [],
    dataOffset: -1,
    dataSize: 0,
  };

  let offset = 12;
  while (offset + 8 <= buffer.length) {
    const id = buffer.subarray(offset, offset + 4).toString("ascii");
    const size = buffer.readUInt32LE(offset + 4);
    const dataStart = offset + 8;
    const dataEnd = dataStart + size;
    if (dataEnd > buffer.length) {
      break;
    }

    info.chunks.push({ id, size });

    if (id === "fmt " && size >= 16) {
      info.audioFormat = buffer.readUInt16LE(dataStart);
      info.channels = buffer.readUInt16LE(dataStart + 2);
      info.sampleRate = buffer.readUInt32LE(dataStart + 4);
      info.byteRate = buffer.readUInt32LE(dataStart + 8);
      info.blockAlign = buffer.readUInt16LE(dataStart + 12);
      info.bitsPerSample = buffer.readUInt16LE(dataStart + 14);
    } else if (id === "data") {
      info.dataOffset = dataStart;
      info.dataSize = size;
    } else if (id === "LIST" && size >= 4) {
      const listType = buffer.subarray(dataStart, dataStart + 4).toString("ascii");
      if (listType === "INFO") {
        let inner = dataStart + 4;
        while (inner + 8 <= dataEnd) {
          const subId = buffer.subarray(inner, inner + 4).toString("ascii");
          const subSize = buffer.readUInt32LE(inner + 4);
          const subStart = inner + 8;
          const subEnd = subStart + subSize;
          if (subEnd > dataEnd) {
            break;
          }
          const value = decodeBufferAsText(buffer.subarray(subStart, subEnd)).replace(/\0/g, "").trim();
          if (value) {
            info.metadata[subId] = value;
          }
          inner = subEnd + (subSize % 2);
        }
      }
    } else if (/^I[A-Z0-9 ]{3}$/.test(id)) {
      const value = decodeBufferAsText(buffer.subarray(dataStart, dataEnd)).replace(/\0/g, "").trim();
      if (value) {
        info.metadata[id] = value;
      }
    }

    offset = dataEnd + (size % 2);
  }

  if (info.byteRate && info.dataSize) {
    info.durationSeconds = info.dataSize / info.byteRate;
  }

  return info;
}

function buildWavSampleStreams(buffer, wavInfo) {
  if (!wavInfo || wavInfo.dataOffset < 0 || !wavInfo.channels || !wavInfo.bitsPerSample) {
    return [];
  }

  const bytesPerSample = Math.ceil(wavInfo.bitsPerSample / 8);
  const frameSize = Math.max(1, wavInfo.channels * bytesPerSample);
  const dataEnd = Math.min(buffer.length, wavInfo.dataOffset + wavInfo.dataSize);
  const sampleCount = Math.min(MAX_AUDIO_SAMPLES, Math.floor((dataEnd - wavInfo.dataOffset) / frameSize));
  const streams = Array.from({ length: wavInfo.channels }, () => []);
  const mixed = [];

  for (let sampleIndex = 0; sampleIndex < sampleCount; sampleIndex += 1) {
    const frameOffset = wavInfo.dataOffset + sampleIndex * frameSize;
    for (let channel = 0; channel < wavInfo.channels; channel += 1) {
      const sampleOffset = frameOffset + channel * bytesPerSample;
      const leastByte = buffer[sampleOffset];
      const bit = leastByte & 1;
      streams[channel].push(bit);
      mixed.push(bit);
    }
  }

  return streams.map((bits, index) => ({
    channel: `CH${index + 1}`,
    bits,
  })).concat(
    mixed.length
      ? [
          {
            channel: "MIX",
            bits: mixed,
          },
        ]
      : [],
  );
}

function collectAudioLSBCandidates(buffer, wavInfo) {
  const streams = buildWavSampleStreams(buffer, wavInfo);
  const results = [];

  streams.forEach((stream) => {
    const decoded = decodeBufferAsText(bitsToBuffer(stream.bits));
    const flags = findFlagCandidates(decoded, `WAV-LSB-${stream.channel}`);
    const printable = extractPrintableSegments(decoded, 10, 10);
    if (!flags.length && !printable.length) {
      return;
    }
    results.push({
      channel: stream.channel,
      flags,
      printable,
    });
  });

  return results;
}

function makeWaveformPng(width, height, drawColumn) {
  const png = new PNG({ width, height });
  png.data.fill(248);
  for (let x = 0; x < width; x += 1) {
    drawColumn(png, x);
  }
  return PNG.sync.write(png);
}

function drawVertical(png, x, top, bottom, r, g, b) {
  const start = Math.max(0, Math.min(top, bottom));
  const end = Math.min(png.height - 1, Math.max(top, bottom));
  for (let y = start; y <= end; y += 1) {
    const offset = (y * png.width + x) * 4;
    png.data[offset] = r;
    png.data[offset + 1] = g;
    png.data[offset + 2] = b;
    png.data[offset + 3] = 255;
  }
}

function renderWavWaveform(buffer, wavInfo, width = 1024, height = 280) {
  if (!wavInfo || wavInfo.dataOffset < 0 || !wavInfo.channels || !wavInfo.bitsPerSample) {
    return null;
  }

  const bytesPerSample = Math.ceil(wavInfo.bitsPerSample / 8);
  const frameSize = Math.max(1, wavInfo.channels * bytesPerSample);
  const dataEnd = Math.min(buffer.length, wavInfo.dataOffset + wavInfo.dataSize);
  const totalFrames = Math.floor((dataEnd - wavInfo.dataOffset) / frameSize);
  if (!totalFrames) {
    return null;
  }

  const channelHeights = Math.max(1, Math.floor(height / Math.max(1, wavInfo.channels)));

  function sampleValue(frameIndex, channel) {
    const offset = wavInfo.dataOffset + frameIndex * frameSize + channel * bytesPerSample;
    if (wavInfo.bitsPerSample === 8) {
      return (buffer[offset] - 128) / 128;
    }
    if (wavInfo.bitsPerSample === 16) {
      return Math.max(-1, Math.min(1, buffer.readInt16LE(offset) / 32768));
    }
    if (wavInfo.bitsPerSample === 24) {
      const value = (buffer[offset + 2] << 16) | (buffer[offset + 1] << 8) | buffer[offset];
      const signed = value & 0x800000 ? value - 0x1000000 : value;
      return Math.max(-1, Math.min(1, signed / 8388608));
    }
    if (wavInfo.bitsPerSample === 32) {
      if (wavInfo.audioFormat === 3) {
        return Math.max(-1, Math.min(1, buffer.readFloatLE(offset)));
      }
      return Math.max(-1, Math.min(1, buffer.readInt32LE(offset) / 2147483648));
    }
    return 0;
  }

  return makeWaveformPng(width, height, (png, x) => {
    const startFrame = Math.floor((x / width) * totalFrames);
    const endFrame = Math.min(totalFrames, Math.floor(((x + 1) / width) * totalFrames) || startFrame + 1);
    for (let channel = 0; channel < wavInfo.channels; channel += 1) {
      let min = 1;
      let max = -1;
      for (let frame = startFrame; frame < endFrame; frame += 1) {
        const value = sampleValue(frame, channel);
        min = Math.min(min, value);
        max = Math.max(max, value);
      }
      const topBase = channel * channelHeights;
      const mid = topBase + Math.floor(channelHeights / 2);
      const top = mid - Math.round(max * (channelHeights * 0.42));
      const bottom = mid - Math.round(min * (channelHeights * 0.42));
      drawVertical(png, x, top, bottom, 20, 132, 120);
    }
  });
}

function iteratePngChunks(buffer) {
  const chunks = [];
  if (detectMagic(buffer) !== "png" || buffer.length < 8) {
    return chunks;
  }

  let offset = 8;
  while (offset + 8 <= buffer.length) {
    const length = buffer.readUInt32BE(offset);
    const type = buffer.subarray(offset + 4, offset + 8).toString("ascii");
    const dataStart = offset + 8;
    const dataEnd = dataStart + length;
    if (dataEnd + 4 > buffer.length) {
      break;
    }
    chunks.push({
      type,
      data: buffer.subarray(dataStart, dataEnd),
    });
    offset = dataEnd + 4;
    if (type === "IEND") {
      break;
    }
  }

  return chunks;
}

function extractPngTextChunks(buffer) {
  const results = [];
  for (const chunk of iteratePngChunks(buffer)) {
    try {
      if (chunk.type === "tEXt") {
        const separator = chunk.data.indexOf(0);
        if (separator !== -1) {
          const keyword = chunk.data.subarray(0, separator).toString("latin1");
          const text = chunk.data.subarray(separator + 1).toString("latin1");
          results.push(`${keyword}: ${text}`);
        }
      } else if (chunk.type === "zTXt") {
        const separator = chunk.data.indexOf(0);
        if (separator !== -1 && separator + 2 <= chunk.data.length) {
          const keyword = chunk.data.subarray(0, separator).toString("latin1");
          const method = chunk.data[separator + 1];
          if (method === 0) {
            const inflated = zlib.inflateSync(chunk.data.subarray(separator + 2)).toString("utf8");
            results.push(`${keyword}: ${inflated}`);
          }
        }
      } else if (chunk.type === "iTXt") {
        let cursor = 0;
        const firstNull = chunk.data.indexOf(0, cursor);
        if (firstNull === -1 || firstNull + 5 > chunk.data.length) {
          continue;
        }
        const keyword = chunk.data.subarray(0, firstNull).toString("utf8");
        const compressionFlag = chunk.data[firstNull + 1];
        const compressionMethod = chunk.data[firstNull + 2];
        cursor = firstNull + 3;
        const languageEnd = chunk.data.indexOf(0, cursor);
        if (languageEnd === -1) {
          continue;
        }
        cursor = languageEnd + 1;
        const translatedEnd = chunk.data.indexOf(0, cursor);
        if (translatedEnd === -1) {
          continue;
        }
        cursor = translatedEnd + 1;
        const textData = chunk.data.subarray(cursor);
        const text =
          compressionFlag === 1 && compressionMethod === 0 ? zlib.inflateSync(textData).toString("utf8") : textData.toString("utf8");
        results.push(`${keyword}: ${text}`);
      }
    } catch (_error) {
      // ignore malformed chunk payloads
    }
  }
  return dedupeStrings(results).slice(0, 20);
}

function bitsToBuffer(bits, bitOrder = "msb") {
  const bytes = [];
  for (let index = 0; index + 7 < bits.length; index += 8) {
    let value = 0;
    if (bitOrder === "lsb") {
      for (let bit = 0; bit < 8; bit += 1) {
        value |= bits[index + bit] << bit;
      }
    } else {
      for (let bit = 0; bit < 8; bit += 1) {
        value = (value << 1) | bits[index + bit];
      }
    }
    bytes.push(value);
  }
  return Buffer.from(bytes);
}

function buildPngStreams(parsed, traversal = "xy") {
  const streams = {
    R: [],
    G: [],
    B: [],
    A: [],
    RGB: [],
    RGBA: [],
  };

  const emit = (x, y) => {
    const index = (y * parsed.width + x) * 4;
    const r = parsed.data[index];
    const g = parsed.data[index + 1];
    const b = parsed.data[index + 2];
    const a = parsed.data[index + 3];
    streams.R.push(r);
    streams.G.push(g);
    streams.B.push(b);
    streams.A.push(a);
    streams.RGB.push(r, g, b);
    streams.RGBA.push(r, g, b, a);
  };

  if (traversal === "yx") {
    for (let x = 0; x < parsed.width; x += 1) {
      for (let y = 0; y < parsed.height; y += 1) {
        emit(x, y);
      }
    }
  } else {
    for (let y = 0; y < parsed.height; y += 1) {
      for (let x = 0; x < parsed.width; x += 1) {
        emit(x, y);
      }
    }
  }

  return streams;
}

function collectPngLSBCandidates(buffer) {
  if (detectMagic(buffer) !== "png") {
    return [];
  }

  let parsed;
  try {
    parsed = PNG.sync.read(buffer, { checkCRC: false });
  } catch (_error) {
    return [];
  }

  const results = [];
  ["xy", "yx"].forEach((traversal) => {
    const streams = buildPngStreams(parsed, traversal);
    Object.entries(streams).forEach(([name, values]) => {
      [0, 1, 2].forEach((bitPlane) => {
        ["msb", "lsb"].forEach((bitOrder) => {
          const bits = values.map((value) => (value >> bitPlane) & 1);
          const decoded = decodeBufferAsText(bitsToBuffer(bits, bitOrder));
          const flags = findFlagCandidates(decoded, `PNG-${traversal}-${name}-bit${bitPlane}-${bitOrder}`);
          const printable = extractPrintableSegments(decoded, 12, 8);
          const score = Math.max(scoreDecodedText(decoded), flags.length ? 24 : 0);
          if (!flags.length && (!printable.length || score < 8)) {
            return;
          }
          results.push({
            traversal,
            channel: name,
            bitPlane,
            bitOrder,
            flags,
            printable,
            score,
          });
        });
      });
    });
  });

  const deduped = new Map();
  results.forEach((item) => {
    const key = `${item.channel}@@${item.bitPlane}@@${item.bitOrder}@@${item.traversal}@@${item.printable.join("||")}@@${item.flags
      .map((entry) => entry.value)
      .join("||")}`;
    const current = deduped.get(key);
    if (!current || item.score > current.score) {
      deduped.set(key, item);
    }
  });

  return Array.from(deduped.values())
    .sort((left, right) => right.score - left.score)
    .slice(0, 18);
}

function markerAfterOffset(buffer, marker, offset) {
  const index = buffer.indexOf(marker, offset);
  return index >= offset ? index : -1;
}

function readUInt16(buffer, offset, littleEndian) {
  return littleEndian ? buffer.readUInt16LE(offset) : buffer.readUInt16BE(offset);
}

function readUInt32(buffer, offset, littleEndian) {
  return littleEndian ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset);
}

function formatIPv4(buffer, offset) {
  return `${buffer[offset]}.${buffer[offset + 1]}.${buffer[offset + 2]}.${buffer[offset + 3]}`;
}

function formatIPv6(buffer, offset) {
  const parts = [];
  for (let index = 0; index < 16; index += 2) {
    parts.push(buffer.readUInt16BE(offset + index).toString(16));
  }
  return parts.join(":").replace(/\b:?(?:0:){2,}/, "::");
}

function parseTcpSegment(buffer) {
  if (buffer.length < 20) {
    return null;
  }
  const srcPort = buffer.readUInt16BE(0);
  const dstPort = buffer.readUInt16BE(2);
  const headerLength = ((buffer[12] >> 4) & 0x0f) * 4;
  if (headerLength < 20 || headerLength > buffer.length) {
    return null;
  }
  return {
    protocol: "tcp",
    srcPort,
    dstPort,
    payload: buffer.subarray(headerLength),
    flags: buffer[13],
  };
}

function parseUdpDatagram(buffer) {
  if (buffer.length < 8) {
    return null;
  }
  const srcPort = buffer.readUInt16BE(0);
  const dstPort = buffer.readUInt16BE(2);
  const length = Math.min(buffer.readUInt16BE(4), buffer.length);
  return {
    protocol: "udp",
    srcPort,
    dstPort,
    payload: buffer.subarray(8, length),
  };
}

function parseIpPacket(buffer) {
  if (!buffer.length) {
    return null;
  }

  const version = buffer[0] >> 4;
  if (version === 4) {
    if (buffer.length < 20) {
      return null;
    }
    const headerLength = (buffer[0] & 0x0f) * 4;
    if (headerLength < 20 || headerLength > buffer.length) {
      return null;
    }
    const protocol = buffer[9];
    const payload = buffer.subarray(headerLength);
    const base = {
      ipVersion: 4,
      srcIp: formatIPv4(buffer, 12),
      dstIp: formatIPv4(buffer, 16),
    };
    if (protocol === 6) {
      const tcp = parseTcpSegment(payload);
      return tcp ? { ...base, ...tcp } : null;
    }
    if (protocol === 17) {
      const udp = parseUdpDatagram(payload);
      return udp ? { ...base, ...udp } : null;
    }
    return { ...base, protocol: String(protocol), payload };
  }

  if (version === 6) {
    if (buffer.length < 40) {
      return null;
    }
    const nextHeader = buffer[6];
    const payload = buffer.subarray(40);
    const base = {
      ipVersion: 6,
      srcIp: formatIPv6(buffer, 8),
      dstIp: formatIPv6(buffer, 24),
    };
    if (nextHeader === 6) {
      const tcp = parseTcpSegment(payload);
      return tcp ? { ...base, ...tcp } : null;
    }
    if (nextHeader === 17) {
      const udp = parseUdpDatagram(payload);
      return udp ? { ...base, ...udp } : null;
    }
    return { ...base, protocol: String(nextHeader), payload };
  }

  return null;
}

function parseFramePayload(frameData, linkType) {
  if (!frameData.length) {
    return null;
  }

  if (linkType === 1) {
    if (frameData.length < 14) {
      return null;
    }
    let etherType = frameData.readUInt16BE(12);
    let offset = 14;
    if ((etherType === 0x8100 || etherType === 0x88a8) && frameData.length >= 18) {
      etherType = frameData.readUInt16BE(16);
      offset = 18;
    }
    if (etherType !== 0x0800 && etherType !== 0x86dd) {
      return null;
    }
    return parseIpPacket(frameData.subarray(offset));
  }

  if (linkType === 101 || linkType === 228) {
    return parseIpPacket(frameData);
  }

  return null;
}

function parseClassicPcap(buffer) {
  if (buffer.length < 24) {
    return [];
  }

  const magicLE = buffer.readUInt32LE(0);
  let littleEndian = true;
  if ([0xa1b2c3d4, 0xa1b23c4d].includes(magicLE)) {
    littleEndian = true;
  } else if ([0xd4c3b2a1, 0x4d3cb2a1].includes(magicLE)) {
    littleEndian = false;
  } else {
    return [];
  }

  const linkType = readUInt32(buffer, 20, littleEndian);
  const frames = [];
  let offset = 24;

  while (offset + 16 <= buffer.length && frames.length < MAX_TRAFFIC_FRAMES) {
    const capturedLength = readUInt32(buffer, offset + 8, littleEndian);
    const dataStart = offset + 16;
    const dataEnd = dataStart + capturedLength;
    if (capturedLength < 0 || dataEnd > buffer.length) {
      break;
    }
    frames.push({
      data: buffer.subarray(dataStart, dataEnd),
      linkType,
    });
    offset = dataEnd;
  }

  return frames;
}

function parsePcapNg(buffer) {
  if (buffer.length < 28 || buffer.readUInt32BE(0) !== 0x0a0d0d0a) {
    return [];
  }

  const bom = buffer.subarray(8, 12);
  const littleEndian = bom.equals(Buffer.from([0x4d, 0x3c, 0x2b, 0x1a]));
  const bigEndian = bom.equals(Buffer.from([0x1a, 0x2b, 0x3c, 0x4d]));
  if (!littleEndian && !bigEndian) {
    return [];
  }

  const le = littleEndian;
  const linkTypes = [];
  const frames = [];
  let offset = 0;

  while (offset + 12 <= buffer.length && frames.length < MAX_TRAFFIC_FRAMES) {
    const blockType = readUInt32(buffer, offset, le);
    const blockLength = readUInt32(buffer, offset + 4, le);
    if (blockLength < 12 || offset + blockLength > buffer.length) {
      break;
    }

    if (blockType === 1 && blockLength >= 20) {
      linkTypes.push(readUInt16(buffer, offset + 8, le));
    } else if (blockType === 6 && blockLength >= 32) {
      const interfaceId = readUInt32(buffer, offset + 8, le);
      const capturedLength = readUInt32(buffer, offset + 20, le);
      const dataStart = offset + 28;
      const dataEnd = dataStart + capturedLength;
      if (dataEnd <= offset + blockLength - 4) {
        frames.push({
          data: buffer.subarray(dataStart, dataEnd),
          linkType: linkTypes[interfaceId] || linkTypes[0] || 1,
        });
      }
    } else if (blockType === 3 && blockLength >= 20) {
      const packetLength = readUInt32(buffer, offset + 8, le);
      const dataStart = offset + 12;
      const dataEnd = dataStart + Math.min(packetLength, blockLength - 16);
      if (dataEnd <= offset + blockLength - 4) {
        frames.push({
          data: buffer.subarray(dataStart, dataEnd),
          linkType: linkTypes[0] || 1,
        });
      }
    }

    offset += blockLength;
  }

  return frames;
}

function parseCaptureFrames(buffer) {
  const magic = detectMagic(buffer);
  if (magic === "pcap") {
    return parseClassicPcap(buffer);
  }
  if (magic === "pcapng") {
    return parsePcapNg(buffer);
  }
  return [];
}

function parseDnsName(buffer, startOffset, depth = 0) {
  if (depth > 8 || startOffset >= buffer.length) {
    return { name: "", nextOffset: startOffset };
  }

  const labels = [];
  let offset = startOffset;
  let jumped = false;
  let nextOffset = startOffset;

  while (offset < buffer.length) {
    const length = buffer[offset];
    if (length === 0) {
      nextOffset = jumped ? nextOffset : offset + 1;
      break;
    }
    if ((length & 0xc0) === 0xc0) {
      if (offset + 1 >= buffer.length) {
        break;
      }
      const pointer = ((length & 0x3f) << 8) | buffer[offset + 1];
      const target = parseDnsName(buffer, pointer, depth + 1);
      if (target.name) {
        labels.push(target.name);
      }
      nextOffset = jumped ? nextOffset : offset + 2;
      jumped = true;
      break;
    }
    if (offset + 1 + length > buffer.length) {
      break;
    }
    labels.push(buffer.subarray(offset + 1, offset + 1 + length).toString("utf8"));
    offset += length + 1;
    if (!jumped) {
      nextOffset = offset;
    }
  }

  return {
    name: labels.join("."),
    nextOffset: nextOffset || offset,
  };
}

function parseDnsMessage(buffer) {
  if (buffer.length < 12) {
    return null;
  }

  const questionCount = buffer.readUInt16BE(4);
  const answerCount = buffer.readUInt16BE(6);
  const questions = [];
  const answers = [];
  let offset = 12;

  for (let index = 0; index < Math.min(questionCount, 20); index += 1) {
    const parsed = parseDnsName(buffer, offset);
    offset = parsed.nextOffset;
    if (offset + 4 > buffer.length) {
      return { questions, answers };
    }
    const type = buffer.readUInt16BE(offset);
    offset += 4;
    if (parsed.name) {
      questions.push(`${parsed.name} [${type}]`);
    }
  }

  for (let index = 0; index < Math.min(answerCount, 30); index += 1) {
    const parsed = parseDnsName(buffer, offset);
    offset = parsed.nextOffset;
    if (offset + 10 > buffer.length) {
      break;
    }
    const type = buffer.readUInt16BE(offset);
    const dataLength = buffer.readUInt16BE(offset + 8);
    const dataOffset = offset + 10;
    if (dataOffset + dataLength > buffer.length) {
      break;
    }

    let value = "";
    if (type === 1 && dataLength === 4) {
      value = formatIPv4(buffer, dataOffset);
    } else if (type === 28 && dataLength === 16) {
      value = formatIPv6(buffer, dataOffset);
    } else if (type === 5 || type === 12 || type === 2) {
      value = parseDnsName(buffer, dataOffset).name;
    } else if (type === 16 && dataLength >= 1) {
      const size = buffer[dataOffset];
      value = buffer.subarray(dataOffset + 1, dataOffset + 1 + Math.min(size, dataLength - 1)).toString("utf8");
    }

    if (parsed.name || value) {
      answers.push(`${parsed.name || "<name>"} [${type}] ${value}`.trim());
    }

    offset = dataOffset + dataLength;
  }

  return {
    questions: dedupeStrings(questions),
    answers: dedupeStrings(answers),
  };
}

function parseTlsServerNames(buffer) {
  if (buffer.length < 9 || buffer[0] !== 0x16) {
    return [];
  }
  const handshakeType = buffer[5];
  if (handshakeType !== 0x01) {
    return [];
  }

  let offset = 9;
  if (offset + 34 > buffer.length) {
    return [];
  }
  offset += 34;

  const sessionLength = buffer[offset];
  offset += 1 + sessionLength;
  if (offset + 2 > buffer.length) {
    return [];
  }

  const cipherLength = buffer.readUInt16BE(offset);
  offset += 2 + cipherLength;
  if (offset + 1 > buffer.length) {
    return [];
  }

  const compressionLength = buffer[offset];
  offset += 1 + compressionLength;
  if (offset + 2 > buffer.length) {
    return [];
  }

  const extensionLength = buffer.readUInt16BE(offset);
  offset += 2;
  const extensionEnd = Math.min(buffer.length, offset + extensionLength);
  const names = [];

  while (offset + 4 <= extensionEnd) {
    const type = buffer.readUInt16BE(offset);
    const length = buffer.readUInt16BE(offset + 2);
    const dataStart = offset + 4;
    const dataEnd = dataStart + length;
    if (dataEnd > extensionEnd) {
      break;
    }

    if (type === 0x0000 && length >= 5) {
      let cursor = dataStart + 2;
      while (cursor + 3 <= dataEnd) {
        const nameType = buffer[cursor];
        const nameLength = buffer.readUInt16BE(cursor + 1);
        const nameStart = cursor + 3;
        const nameEnd = nameStart + nameLength;
        if (nameEnd > dataEnd) {
          break;
        }
        if (nameType === 0) {
          names.push(buffer.subarray(nameStart, nameEnd).toString("utf8"));
        }
        cursor = nameEnd;
      }
    }

    offset = dataEnd;
  }

  return dedupeStrings(names).slice(0, 12);
}

function parseHttpPayload(buffer) {
  if (!buffer.length) {
    return null;
  }

  const text = decodeBufferAsText(buffer.subarray(0, Math.min(buffer.length, MAX_HTTP_BODY_BYTES + 4096)));
  const headerEnd = text.indexOf("\r\n\r\n") !== -1 ? text.indexOf("\r\n\r\n") : text.indexOf("\n\n");
  const splitIndex = headerEnd === -1 ? text.length : headerEnd;
  const headerText = text.slice(0, splitIndex);
  const lines = headerText.split(/\r?\n/).filter(Boolean);
  if (!lines.length) {
    return null;
  }

  const firstLine = lines[0].trim();
  const methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"];
  const isRequest = methods.some((method) => firstLine.startsWith(`${method} `));
  const isResponse = firstLine.startsWith("HTTP/");
  if (!isRequest && !isResponse) {
    return null;
  }

  const headers = {};
  lines.slice(1).forEach((line) => {
    const separator = line.indexOf(":");
    if (separator === -1) {
      return;
    }
    const key = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    if (key) {
      headers[key] = value;
    }
  });

  let bodyBuffer = Buffer.alloc(0);
  if (headerEnd !== -1) {
    const delimiterLength = text.indexOf("\r\n\r\n") !== -1 ? 4 : 2;
    const headerBytes = Buffer.from(text.slice(0, splitIndex + delimiterLength), "utf8").length;
    bodyBuffer = buffer.subarray(Math.min(headerBytes, buffer.length), Math.min(buffer.length, headerBytes + MAX_HTTP_BODY_BYTES));
  }

  const result = {
    type: isRequest ? "request" : "response",
    firstLine,
    headers,
    bodyBuffer,
  };

  if (isRequest) {
    const match = firstLine.match(/^([A-Z]+)\s+(\S+)/);
    if (match) {
      result.method = match[1];
      result.path = match[2];
    }
  } else {
    const match = firstLine.match(/^HTTP\/\d\.\d\s+(\d+)/);
    if (match) {
      result.statusCode = Number(match[1]);
    }
  }

  return result;
}

function normalizeSessionKey(packet) {
  const left = `${packet.srcIp}:${packet.srcPort}`;
  const right = `${packet.dstIp}:${packet.dstPort}`;
  return [left, right].sort().join(" <-> ");
}

function analyzeTrafficBuffer(buffer) {
  const frames = parseCaptureFrames(buffer);
  const summary = {
    frameCount: frames.length,
    sessionCount: 0,
    httpRequests: [],
    dnsQueries: [],
    dnsAnswers: [],
    tlsServerNames: [],
    cookies: [],
    tokens: [],
    sessions: [],
    exportedObjects: [],
  };

  if (!frames.length) {
    return summary;
  }

  const sessions = new Map();

  frames.forEach((frame) => {
    const packet = parseFramePayload(frame.data, frame.linkType);
    if (!packet || !packet.payload) {
      return;
    }

    if (packet.protocol === "tcp" || packet.protocol === "udp") {
      const sessionKey = normalizeSessionKey(packet);
      const current = sessions.get(sessionKey) || {
        key: sessionKey,
        protocol: packet.protocol.toUpperCase(),
        endpoints: `${packet.srcIp}:${packet.srcPort} -> ${packet.dstIp}:${packet.dstPort}`,
        packets: 0,
        bytes: 0,
      };
      current.packets += 1;
      current.bytes += packet.payload.length;
      sessions.set(sessionKey, current);
    }

    if (packet.protocol === "udp" && (packet.srcPort === 53 || packet.dstPort === 53)) {
      const dns = parseDnsMessage(packet.payload);
      if (dns) {
        summary.dnsQueries.push(...dns.questions);
        summary.dnsAnswers.push(...dns.answers);
      }
      return;
    }

    if (packet.protocol !== "tcp" || !packet.payload.length) {
      return;
    }

    const http = parseHttpPayload(packet.payload);
    if (http) {
      if (http.type === "request") {
        summary.httpRequests.push(
          `${http.method || "HTTP"} ${http.headers.host || packet.dstIp}${http.path || ""}`,
        );
      }
      if (http.headers.cookie) {
        summary.cookies.push(http.headers.cookie);
      }
      if (http.headers.authorization || http.headers["x-token"] || http.headers.token) {
        summary.tokens.push(http.headers.authorization || http.headers["x-token"] || http.headers.token);
      }

      if (summary.exportedObjects.length < MAX_HTTP_OBJECTS) {
        const body = http.bodyBuffer || Buffer.alloc(0);
        const contentType = String(http.headers["content-type"] || "");
        const isTextLike = /json|xml|html|text|javascript|x-www-form-urlencoded/i.test(contentType);
        const baseName = `http-${String(summary.exportedObjects.length + 1).padStart(3, "0")}`;
        summary.exportedObjects.push({
          name: `${baseName}-${http.type}.txt`,
          content: Buffer.from(`${http.firstLine}\n${Object.entries(http.headers)
            .map(([key, value]) => `${key}: ${value}`)
            .join("\n")}\n`, "utf8"),
        });
        if (body.length) {
          let ext = ".bin";
          if (/json/i.test(contentType)) {
            ext = ".json";
          } else if (/html/i.test(contentType)) {
            ext = ".html";
          } else if (/xml/i.test(contentType)) {
            ext = ".xml";
          } else if (/javascript/i.test(contentType)) {
            ext = ".js";
          } else if (isTextLike) {
            ext = ".txt";
          }
          summary.exportedObjects.push({
            name: `${baseName}-body${ext}`,
            content: body,
          });
        }
      }
      return;
    }

    const tlsNames = parseTlsServerNames(packet.payload);
    if (tlsNames.length) {
      summary.tlsServerNames.push(...tlsNames);
    }
  });

  summary.dnsQueries = dedupeStrings(summary.dnsQueries).slice(0, 30);
  summary.dnsAnswers = dedupeStrings(summary.dnsAnswers).slice(0, 30);
  summary.httpRequests = dedupeStrings(summary.httpRequests).slice(0, 30);
  summary.tlsServerNames = dedupeStrings(summary.tlsServerNames).slice(0, 20);
  summary.cookies = dedupeStrings(summary.cookies).slice(0, 12);
  summary.tokens = dedupeStrings(summary.tokens).slice(0, 12);
  summary.sessions = Array.from(sessions.values())
    .sort((left, right) => right.bytes - left.bytes)
    .slice(0, 12);
  summary.sessionCount = sessions.size;

  return summary;
}

function buildTrafficSummaryText(fileName, summary) {
  const lines = [
    `# TRAFFIC SUMMARY`,
    `file: ${fileName}`,
    `frames: ${summary.frameCount}`,
    `sessions: ${summary.sessionCount}`,
    "",
  ];

  if (summary.httpRequests.length) {
    lines.push("# HTTP");
    summary.httpRequests.forEach((item) => lines.push(item));
    lines.push("");
  }
  if (summary.dnsQueries.length || summary.dnsAnswers.length) {
    lines.push("# DNS");
    summary.dnsQueries.forEach((item) => lines.push(`Q ${item}`));
    summary.dnsAnswers.forEach((item) => lines.push(`A ${item}`));
    lines.push("");
  }
  if (summary.tlsServerNames.length) {
    lines.push("# TLS-SNI");
    summary.tlsServerNames.forEach((item) => lines.push(item));
    lines.push("");
  }
  if (summary.cookies.length) {
    lines.push("# COOKIE");
    summary.cookies.forEach((item) => lines.push(item));
    lines.push("");
  }
  if (summary.tokens.length) {
    lines.push("# TOKEN");
    summary.tokens.forEach((item) => lines.push(item));
    lines.push("");
  }
  if (summary.sessions.length) {
    lines.push("# SESSIONS");
    summary.sessions.forEach((item) => lines.push(`${item.protocol} ${item.endpoints} packets=${item.packets} bytes=${item.bytes}`));
    lines.push("");
  }

  return `${lines.join("\n")}\n`;
}

function decodePdfLiteralString(value) {
  return String(value || "")
    .replace(/\\([\\()])/g, "$1")
    .replace(/\\n/g, "\n")
    .replace(/\\r/g, "\r")
    .replace(/\\t/g, "\t");
}

function findPdfStreams(buffer) {
  const streams = [];
  let offset = 0;

  while (offset < buffer.length) {
    const streamIndex = buffer.indexOf(Buffer.from("stream"), offset);
    if (streamIndex === -1) {
      break;
    }

    let dataStart = streamIndex + 6;
    if (buffer[dataStart] === 0x0d && buffer[dataStart + 1] === 0x0a) {
      dataStart += 2;
    } else if (buffer[dataStart] === 0x0a || buffer[dataStart] === 0x0d) {
      dataStart += 1;
    }

    const endIndex = buffer.indexOf(Buffer.from("endstream"), dataStart);
    if (endIndex === -1) {
      break;
    }

    const dictionaryText = buffer.subarray(Math.max(0, streamIndex - 256), streamIndex).toString("latin1");
    const raw = buffer.subarray(dataStart, endIndex);
    const trimmed =
      raw.length > 1 && raw[raw.length - 2] === 0x0d && raw[raw.length - 1] === 0x0a
        ? raw.subarray(0, raw.length - 2)
        : raw.length > 0 && (raw[raw.length - 1] === 0x0a || raw[raw.length - 1] === 0x0d)
          ? raw.subarray(0, raw.length - 1)
          : raw;

    streams.push({
      dictionaryText,
      raw: trimmed,
    });

    offset = endIndex + 9;
  }

  return streams;
}

function analyzePdfBuffer(buffer) {
  if (detectMagic(buffer) !== "pdf") {
    return null;
  }

  const latin = buffer.toString("latin1");
  const utf = decodeBufferAsText(buffer);
  const metadata = {};
  const urls = dedupeStrings(Array.from(utf.matchAll(/\bhttps?:\/\/[^\s"'<>]+/gi)).map((match) => match[0]).slice(0, 20));
  const xmpPackets = dedupeStrings(Array.from(latin.matchAll(/<x:xmpmeta[\s\S]{0,200000}?<\/x:xmpmeta>/gi)).map((match) => match[0]).slice(0, 6));
  const extractedStreams = [];

  Array.from(latin.matchAll(/\/(Title|Author|Subject|Keywords|Creator|Producer)\s*\(((?:\\.|[^\\)]){1,400})\)/g)).forEach((match) => {
    metadata[match[1]] = decodePdfLiteralString(match[2]);
  });

  findPdfStreams(buffer).forEach((stream, index) => {
    let decodedBuffer = stream.raw;
    if (/FlateDecode/i.test(stream.dictionaryText)) {
      try {
        decodedBuffer = zlib.inflateSync(stream.raw, { maxOutputLength: MAX_TEXT_BYTES });
      } catch (_error) {
        return;
      }
    }

    const decodedText = decodeBufferAsText(decodedBuffer);
    const printable = extractPrintableSegments(decodedText, 8, 20);
    const flags = findFlagCandidates(decodedText, `PDF-STREAM-${index + 1}`);
    if (!printable.length && !flags.length) {
      return;
    }

    extractedStreams.push({
      index: index + 1,
      flags,
      printable,
      text: decodedText.slice(0, MAX_TEXT_BYTES),
    });
  });

  return {
    metadata,
    urls,
    xmpPackets,
    extractedStreams,
  };
}

function buildPdfSummaryText(fileName, report) {
  const lines = [`# PDF SUMMARY`, `file: ${fileName}`, ""];

  const metadataEntries = Object.entries(report.metadata || {});
  if (metadataEntries.length) {
    lines.push("# METADATA");
    metadataEntries.forEach(([key, value]) => lines.push(`${key}: ${value}`));
    lines.push("");
  }
  if (report.urls && report.urls.length) {
    lines.push("# URL");
    report.urls.forEach((item) => lines.push(item));
    lines.push("");
  }
  if (report.extractedStreams && report.extractedStreams.length) {
    lines.push("# STREAMS");
    report.extractedStreams.forEach((item) => {
      lines.push(`stream-${item.index}`);
      item.flags.forEach((flag) => lines.push(flag.value));
      item.printable.forEach((entry) => lines.push(entry));
      lines.push("");
    });
  }
  if (report.xmpPackets && report.xmpPackets.length) {
    lines.push("# XMP");
    report.xmpPackets.forEach((_item, index) => lines.push(`xmp-${index + 1}.xml`));
    lines.push("");
  }

  return `${lines.join("\n")}\n`;
}

async function buildArtifactSignals(filePath) {
  const extension = path.extname(filePath).toLowerCase();
  const sampleLimit =
    extension === ".txt"
      ? MAX_TEXT_BYTES
      : [".wav", ".mp3", ".flac", ".ogg", ".m4a"].includes(extension)
        ? MAX_AUDIO_BYTES
      : [".pcap", ".pcapng", ".cap"].includes(extension)
        ? MAX_TRAFFIC_BYTES
        : MAX_SAMPLE_BYTES;
  const { stat, buffer } = readSample(filePath, sampleLimit);
  const descriptor = detectFamily(filePath, buffer);
  const artifact = {
    id: filePath,
    path: filePath,
    name: path.basename(filePath),
    extension: extension || "",
    family: descriptor.family,
    familyLabel: COPY.families[descriptor.family],
    badge: descriptor.badge,
    size: stat.size,
    sizeLabel: formatBytes(stat.size),
    summary: "",
    highlights: [],
    suggestions: [],
    keywords: [],
    flagCandidates: [],
    actions: [],
    embeddedPayloads: [],
  };

  let searchableText = "";

  if (artifact.family === "text" || artifact.family === "document") {
    searchableText = decodeBufferAsText(buffer);
  } else {
    searchableText = dedupeStrings(extractAsciiStrings(buffer, 4).concat(extractUnicodeStrings(buffer, 4))).join("\n");
  }

  const encodedSegments = findEncodedSegments(searchableText);
  const decodedSegments = decodeInterestingSegments(encodedSegments);
  const smartDecoded = artifact.family === "text" || artifact.family === "document" ? smartDecodeTextContent(buffer) : [];
  const directFlags = findFlagCandidates(searchableText, artifact.name);
  const decodedFlags = decodedSegments.flatMap((item) => findFlagCandidates(item.value, `${artifact.name} (${item.type})`));
  const smartFlags = smartDecoded.flatMap((item) => findFlagCandidates(item.value, `${artifact.name} (${item.label})`));
  artifact.flagCandidates = dedupeStrings([...directFlags, ...decodedFlags, ...smartFlags].map((item) => `${item.value}@@${item.source}`)).map((entry) => {
    const [value, source] = entry.split("@@");
    return { value, source };
  });

  const lowered = normalizeText(searchableText);
  let embeddedPayloads = detectEmbeddedPayloads(buffer, artifact.family === "image" ? 128 : 64).filter((item) => item.offset > 0);
  if ((artifact.family === "archive" && artifact.badge === "ZIP") || isOfficePackageExtension(extension)) {
    embeddedPayloads = embeddedPayloads.filter((item) => item.id !== "zip");
  }
  artifact.embeddedPayloads = embeddedPayloads;
  const trafficSummary = artifact.family === "network" ? analyzeTrafficBuffer(buffer) : null;
  const pdfReport = artifact.badge === "PDF" ? analyzePdfBuffer(buffer) : null;
  let imageRaster = null;
  let qrPayload = null;
  let barcodePayload = null;
  let wavInfo = null;
  let audioLSB = [];
  if (artifact.family === "image") {
    try {
      imageRaster = decodeImageRaster(buffer);
      qrPayload = imageRaster ? detectQrPayload(buffer) : null;
      barcodePayload = imageRaster ? await detectBarcodePayload(filePath) : null;
    } catch (_error) {
      imageRaster = null;
      qrPayload = null;
      barcodePayload = null;
    }
  }
  if (artifact.family === "audio" && artifact.badge === "WAV") {
    try {
      wavInfo = parseWavBuffer(buffer);
      audioLSB = wavInfo ? collectAudioLSBCandidates(buffer, wavInfo) : [];
    } catch (_error) {
      wavInfo = null;
      audioLSB = [];
    }
  }

  if (artifact.family === "image") {
    artifact.summary = "\u56fe\u50cf\u7c7b\u9644\u4ef6\uff0c\u9002\u5408\u68c0\u67e5\u5143\u6570\u636e\u3001\u9690\u5199\u3001\u50cf\u7d20\u901a\u9053\u548c\u5c3e\u90e8\u9644\u52a0\u6570\u636e\u3002";
    const pngSize = readPngDimensions(buffer);
    if (imageRaster && !pngSize) {
      artifact.highlights.push(`${artifact.badge} ${imageRaster.width} x ${imageRaster.height}`);
    }
    if (pngSize) {
      artifact.highlights.push(`PNG ${pngSize.width} x ${pngSize.height}`);
      artifact.keywords.push("image", "png");
      artifact.actions.push({
        id: "extract-png-text",
        label: "\u63d0\u53d6 PNG \u6587\u672c\u5757",
      });
      artifact.actions.push({
        id: "extract-png-lsb",
        label: "\u63d0\u53d6 PNG \u4f4e\u4f4d\u5e73\u9762",
      });
      const textChunks = extractPngTextChunks(buffer);
      if (textChunks.length) {
        artifact.highlights.push(`PNG \u5185\u90e8\u6587\u672c\u5757 ${textChunks.length} \u6761\u3002`);
      }
      const bitCandidates = collectPngLSBCandidates(buffer);
      if (bitCandidates.length) {
        artifact.highlights.push(`PNG \u4f4e\u4f4d\u5e73\u9762\u547d\u4e2d ${bitCandidates.length} \u7ec4\u53ef\u8bfb\u7ebf\u7d22\u3002`);
      }
    }
    if (imageRaster) {
      artifact.actions.push({
        id: "extract-image-views",
        label: "\u5bfc\u51fa\u56fe\u50cf\u901a\u9053",
      });
    }
    if (embeddedPayloads.length) {
      artifact.highlights.push(`\u68c0\u6d4b\u5230 ${embeddedPayloads.length} \u4e2a\u9644\u52a0\u8d44\u6599\u5934\uff0c\u53ef\u80fd\u5b58\u5728\u5d4c\u5165\u6587\u4ef6\u3002`);
      artifact.keywords.push(...embeddedPayloads.map((item) => item.id));
      artifact.actions.push({
        id: "extract-appended-payloads",
        label: "\u63d0\u53d6\u9644\u52a0\u8d44\u6599",
      });
    }
    if (qrPayload) {
      artifact.highlights.push("\u68c0\u6d4b\u5230\u4e8c\u7ef4\u7801\u5185\u5bb9\u3002");
      artifact.keywords.push("qr", "code");
      artifact.actions.push({
        id: "extract-image-qr",
        label: "\u63d0\u53d6\u4e8c\u7ef4\u7801",
      });
      artifact.flagCandidates = dedupeStrings(
        artifact.flagCandidates.map((item) => `${item.value}@@${item.source}`).concat(findFlagCandidates(qrPayload, `${artifact.name} (QR)`).map((item) => `${item.value}@@${item.source}`)),
      ).map((entry) => {
        const [value, source] = entry.split("@@");
        return { value, source };
      });
    }
    if (barcodePayload && barcodePayload !== qrPayload) {
      artifact.highlights.push("\u68c0\u6d4b\u5230\u4e00\u7ef4\u6761\u7801\u5185\u5bb9\u3002");
      artifact.keywords.push("barcode", "code");
      artifact.actions.push({
        id: "extract-image-barcode",
        label: "\u63d0\u53d6\u6761\u7801",
      });
      artifact.flagCandidates = dedupeStrings(
        artifact.flagCandidates
          .map((item) => `${item.value}@@${item.source}`)
          .concat(findFlagCandidates(barcodePayload, `${artifact.name} (BARCODE)`).map((item) => `${item.value}@@${item.source}`)),
      ).map((entry) => {
        const [value, source] = entry.split("@@");
        return { value, source };
      });
    }
    if (lowered.includes("flag")) {
      artifact.highlights.push("\u56fe\u50cf strings \u91cc\u51fa\u73b0 flag \u5173\u952e\u5b57\u3002");
    }
    if (artifact.badge === "JPEG") {
      artifact.actions.push({
        id: "extract-image-metadata",
        label: "\u63d0\u53d6\u56fe\u50cf\u5143\u6570\u636e",
      });
      artifact.actions.push({
        id: "extract-jpeg-segments",
        label: "\u63d0\u53d6 JPEG \u6bb5",
      });
      const jpegSegments = parseJpegSegments(buffer);
      if (jpegSegments.length) {
        artifact.highlights.push(`JPEG \u6bb5 ${jpegSegments.length} \u4e2a\u3002`);
      }
      const xmpCount = jpegSegments.filter((item) => item.kind === "xmp").length;
      const commentCount = jpegSegments.filter((item) => item.kind === "comment").length;
      const photoshopCount = jpegSegments.filter((item) => item.kind === "photoshop").length;
      if (xmpCount) {
        artifact.highlights.push(`JPEG XMP \u7247\u6bb5 ${xmpCount} \u4e2a\u3002`);
      }
      if (commentCount) {
        artifact.highlights.push(`JPEG \u6ce8\u91ca\u6bb5 ${commentCount} \u4e2a\u3002`);
      }
      if (photoshopCount) {
        artifact.highlights.push(`JPEG Photoshop APP13 \u7247\u6bb5 ${photoshopCount} \u4e2a\u3002`);
      }
      try {
        const metadata = ExifParser.create(buffer).parse();
        const tagCount = Object.keys(metadata.tags || {}).length;
        if (tagCount) {
          artifact.highlights.push(`JPEG EXIF \u6807\u7b7e ${tagCount} \u6761\u3002`);
        }
      } catch (_error) {
        // ignore
      }
    }
    artifact.suggestions.push("\u67e5 EXIF/XMP/COM/APP \u6bb5\u3001\u901a\u9053\u9690\u5199\u3001LSB \u548c\u5c3e\u90e8\u9644\u52a0\u6587\u4ef6\u3002");
  } else if (artifact.family === "audio") {
    artifact.summary = "\u97f3\u9891\u7c7b\u9644\u4ef6\uff0c\u9002\u5408\u68c0\u67e5 RIFF \u5757\u3001\u5143\u6570\u636e\u3001strings\u3001PCM LSB \u548c\u53ef\u89c6\u5316\u8f68\u8ff9\u3002";
    artifact.keywords.push("audio");
    if (wavInfo) {
      artifact.highlights.push(
        `WAV ${wavInfo.channels}ch ${wavInfo.sampleRate}Hz ${wavInfo.bitsPerSample}bit ${wavInfo.durationSeconds.toFixed(2)}s`,
      );
      if (Object.keys(wavInfo.metadata).length) {
        artifact.highlights.push(`WAV \u5143\u6570\u636e ${Object.keys(wavInfo.metadata).length} \u6761\u3002`);
      }
      if (audioLSB.length) {
        artifact.highlights.push(`WAV LSB \u547d\u4e2d ${audioLSB.length} \u7ec4\u53ef\u8bfb\u7ebf\u7d22\u3002`);
      }
      artifact.actions.push({
        id: "extract-audio-clues",
        label: "\u63d0\u53d6\u97f3\u9891\u7ebf\u7d22",
      });
      artifact.actions.push({
        id: "extract-audio-views",
        label: "\u5bfc\u51fa\u97f3\u9891\u89c6\u56fe",
      });
    }
    artifact.actions.push({
      id: "extract-strings",
      label: "\u5bfc\u51fa strings",
    });
    artifact.suggestions.push("\u5148\u770b fmt/data/LIST \u5757\uff0c\u518d\u62bd strings\u3001LSB \u5019\u9009\u548c\u6ce2\u5f62\u56fe\u3002");
  } else if (artifact.family === "network") {
    artifact.summary = "\u6d41\u91cf\u7c7b\u9644\u4ef6\uff0c\u4f18\u5148\u6309 HTTP\u3001DNS\u3001TLS \u548c TCP \u4f1a\u8bdd\u8fd8\u539f\u7ebf\u7d22\u3002";
    artifact.keywords.push("pcap", "traffic", "network");
    if (stat.size > sampleLimit) {
      artifact.highlights.push(`\u6d41\u91cf\u6587\u4ef6\u8f83\u5927\uff0c\u5f53\u524d\u5148\u5206\u6790\u524d ${formatBytes(sampleLimit)} \u5185\u5bb9\u3002`);
    }
    if (trafficSummary && trafficSummary.frameCount) {
      artifact.highlights.push(`\u5df2\u89e3\u6790 ${trafficSummary.frameCount} \u5e27\uff0c\u547d\u4e2d ${trafficSummary.sessionCount} \u4e2a\u4f1a\u8bdd\u3002`);
    }
    if (trafficSummary && trafficSummary.httpRequests.length) {
      artifact.highlights.push(`\u53d1\u73b0 HTTP \u8bf7\u6c42 ${trafficSummary.httpRequests.length} \u6761\u3002`);
      artifact.keywords.push("http", "web");
    }
    if (trafficSummary && trafficSummary.dnsQueries.length) {
      artifact.highlights.push(`\u53d1\u73b0 DNS \u57df\u540d ${trafficSummary.dnsQueries.length} \u6761\u3002`);
      artifact.keywords.push("dns");
    }
    if (trafficSummary && trafficSummary.tlsServerNames.length) {
      artifact.highlights.push(`TLS SNI \u57df\u540d ${trafficSummary.tlsServerNames.length} \u6761\u3002`);
      artifact.keywords.push("tls");
    }
    if (trafficSummary && (trafficSummary.cookies.length || trafficSummary.tokens.length)) {
      artifact.highlights.push("\u53d1\u73b0 Cookie / Token / Authorization \u7c7b\u4fe1\u606f\u3002");
      artifact.keywords.push("cookie", "session");
    }
    if (lowered.includes("http/1.") || lowered.includes("get /") || lowered.includes("post /") || lowered.includes("host:")) {
      artifact.highlights.push("\u53d1\u73b0 HTTP \u8bf7\u6c42\u6216 Host \u7ebf\u7d22\u3002");
      artifact.keywords.push("http", "web");
    }
    if (lowered.includes("cookie") || lowered.includes("authorization") || lowered.includes("token")) {
      artifact.highlights.push("\u53d1\u73b0 Cookie / Token / Authorization \u7c7b\u4fe1\u606f\u3002");
      artifact.keywords.push("cookie", "session");
    }
    if (lowered.includes("dns")) {
      artifact.highlights.push("\u53d1\u73b0 DNS \u5173\u952e\u5b57\u7ebf\u7d22\u3002");
    }
    artifact.suggestions.push("Wireshark \u53ef\u4f18\u5148\u8fc7\u6ee4 http\u3001dns\u3001tcp.stream\uff0c\u67e5\u5bf9\u8c61\u5bfc\u51fa\u548c\u4f1a\u8bdd\u91cd\u7ec4\u3002");
    artifact.actions.push({
      id: "extract-traffic-sessions",
      label: "\u63d0\u53d6\u6d41\u91cf\u4f1a\u8bdd",
    });
    artifact.actions.push({
      id: "extract-strings",
      label: "\u5bfc\u51fa strings",
    });
  } else if (artifact.family === "archive") {
    artifact.summary = "\u538b\u7f29\u5305\u7c7b\u9644\u4ef6\uff0c\u5e38\u89c1\u7ebf\u7d22\u662f\u5d4c\u5957\u6587\u4ef6\u3001\u8bc4\u8bba\u3001\u989d\u5916\u76ee\u5f55\u6216\u5bc6\u7801\u63d0\u793a\u3002";
    artifact.keywords.push("archive", "zip");
    if (artifact.badge === "GZIP") {
      artifact.highlights.push("GZIP \u538b\u7f29\u6d41\uff0c\u53ef\u76f4\u63a5\u89e3\u538b\u7ee7\u7eed\u9012\u5f52\u5206\u6790\u3002");
    }
    artifact.suggestions.push("\u89e3\u538b\u540e\u68c0\u67e5\u9690\u85cf\u76ee\u5f55\u3001\u6ce8\u91ca\u3001\u5d4c\u5957\u6587\u4ef6\u548c\u4e0e flag \u76f8\u5173\u7684\u6587\u4ef6\u540d\u3002");
    artifact.actions.push({
      id: "extract-archive",
      label: artifact.badge === "GZIP" ? "\u89e3\u538b GZIP" : "\u89e3\u5305 ZIP",
    });
  } else if (artifact.family === "binary") {
    artifact.summary = "\u4e8c\u8fdb\u5236\u7c7b\u9644\u4ef6\uff0c\u53ef\u4ece strings\u3001\u5bfc\u5165\u8868\u3001\u6821\u9a8c\u5b57\u7b26\u4e32\u548c\u63a7\u5236\u6d41\u5207\u5165\u3002";
    artifact.keywords.push("binary");
    const unicodeStrings = extractUnicodeStrings(buffer, 4, 120);
    if (artifact.badge === "ELF" || extension === ".elf") {
      artifact.highlights.push("ELF \u4e8c\u8fdb\u5236\uff0c\u504f\u5411\u9006\u5411\u6216 pwn \u6d41\u7a0b\u3002");
      artifact.keywords.push("elf", "reverse");
    }
    if (unicodeStrings.length) {
      artifact.highlights.push(`\u63d0\u53d6\u5230 ${unicodeStrings.length} \u6761 UTF-16 \u5b57\u7b26\u4e32\u3002`);
    }
    if (lowered.includes("glibc") || lowered.includes("malloc") || lowered.includes("free(") || lowered.includes("stack smashing")) {
      artifact.highlights.push("\u51fa\u73b0 libc \u6216\u5185\u5b58\u7ba1\u7406\u5173\u952e\u5b57\u3002");
      artifact.keywords.push("libc", "heap");
    }
    if (lowered.includes("flag") || lowered.includes("correct") || lowered.includes("wrong")) {
      artifact.highlights.push("strings \u91cc\u51fa\u73b0\u6821\u9a8c\u6216 flag \u76f8\u5173\u5b57\u7b26\u4e32\u3002");
    }
    artifact.suggestions.push("\u5148 strings\uff0c\u518d\u67e5\u5bfc\u5165\u51fd\u6570\u3001\u6bd4\u8f83\u903b\u8f91\u548c flag \u751f\u6210\u8def\u5f84\u3002");
    artifact.actions.push({
      id: "extract-strings",
      label: "\u5bfc\u51fa strings",
    });
  } else if (artifact.family === "text") {
    artifact.summary = "\u6587\u672c\u7c7b\u9644\u4ef6\uff0c\u4f18\u5148\u68c0\u67e5 flag \u6837\u5f0f\u3001base64\u3001hex\u3001URL \u548c\u9690\u85cf\u63d0\u793a\u3002";
    artifact.keywords.push("text");
    if (encodedSegments.base64.length) {
      artifact.highlights.push(`\u53d1\u73b0 ${encodedSegments.base64.length} \u6bb5\u53ef\u7591 Base64 \u5185\u5bb9\u3002`);
      artifact.keywords.push("base64", "encoding");
    }
    if (encodedSegments.hex.length) {
      artifact.highlights.push(`\u53d1\u73b0 ${encodedSegments.hex.length} \u6bb5\u53ef\u7591 Hex \u5185\u5bb9\u3002`);
      artifact.keywords.push("hex", "encoding");
    }
    if (decodedSegments.length) {
      artifact.highlights.push("\u5df2\u4ece\u7f16\u7801\u6bb5\u4e2d\u8fd8\u539f\u51fa\u53ef\u8bfb\u5185\u5bb9\u3002");
      artifact.actions.push({
        id: "decode-encoded-text",
        label: "\u89e3\u7801 Base64 / Hex",
      });
    }
    if (smartDecoded.some((item) => item.type === "xor" || item.type === "rot13" || item.type === "base32")) {
      artifact.highlights.push("\u68c0\u6d4b\u5230\u53ef\u8fdb\u4e00\u6b65\u89e3\u7801\u7684 XOR / ROT13 / Base32 \u7ebf\u7d22\u3002");
      if (!artifact.actions.some((item) => item.id === "decode-encoded-text")) {
        artifact.actions.push({
          id: "decode-encoded-text",
          label: "\u89e3\u7801 Base64 / Hex / XOR",
        });
      }
    }
    artifact.suggestions.push("\u5bf9\u6587\u672c\u4f18\u5148\u505a base64/hex/XOR/ROT \u548c\u5206\u5757\u91cd\u7ec4\u3002");
  } else if (artifact.family === "document") {
    artifact.summary = "\u6587\u6863\u7c7b\u9644\u4ef6\uff0c\u9700\u8981\u68c0\u67e5\u5185\u5d4c\u6587\u672c\u3001\u5173\u952e\u5b57\u3001\u9644\u4ef6\u548c\u5143\u6570\u636e\u3002";
    if (artifact.badge === "PDF" && pdfReport) {
      const metadataCount = Object.keys(pdfReport.metadata || {}).length;
      if (metadataCount) {
        artifact.highlights.push(`PDF \u5143\u6570\u636e ${metadataCount} \u6761\u3002`);
      }
      if (pdfReport.urls.length) {
        artifact.highlights.push(`PDF URL ${pdfReport.urls.length} \u6761\u3002`);
      }
      if (pdfReport.xmpPackets.length) {
        artifact.highlights.push(`PDF XMP \u5305 ${pdfReport.xmpPackets.length} \u4e2a\u3002`);
      }
      if (pdfReport.extractedStreams.length) {
        artifact.highlights.push(`PDF \u53ef\u8bfb stream ${pdfReport.extractedStreams.length} \u4e2a\u3002`);
      }
      artifact.actions.push({
        id: "extract-pdf-content",
        label: "\u63d0\u53d6 PDF \u5185\u5bb9",
      });
      artifact.suggestions.push("\u62bd\u51fa PDF \u5143\u6570\u636e\u3001XMP\u3001Flate stream \u548c URL\uff0c\u68c0\u67e5\u662f\u5426\u9690\u85cf flag \u6216\u7ebf\u7d22\u3002");
    } else if (isOfficePackageExtension(extension)) {
      artifact.highlights.push("\u6587\u6863\u662f\u6253\u5305\u683c\u5f0f\uff0c\u53ef\u4ee5\u76f4\u63a5\u62c6\u51fa XML\u3001\u5a92\u4f53\u548c\u5d4c\u5165\u5bf9\u8c61\u3002");
      artifact.actions.push({
        id: "extract-document-package",
        label: "\u62c6\u6587\u6863\u5305",
      });
      artifact.suggestions.push("\u5148\u62c6\u51fa word/xl/ppt \u5185\u90e8 XML \u548c media \u76ee\u5f55\uff0c\u518d\u9012\u5f52\u5206\u6790\u3002");
    } else {
      artifact.suggestions.push("\u5c1d\u8bd5\u62bd\u51fa\u6587\u672c\u3001\u627e\u9690\u85cf\u9875\u9762/\u9644\u4ef6\uff0c\u5e76\u68c0\u67e5\u5143\u6570\u636e\u3002");
    }
  } else {
    artifact.summary = "\u672a\u660e\u786e\u5206\u7c7b\u7684\u9644\u4ef6\uff0c\u53ef\u5148\u62bd strings \u548c\u8bc6\u522b\u6587\u4ef6\u5934\u3001\u5c3e\u90e8\u6216\u5d4c\u5957\u5185\u5bb9\u3002";
    artifact.suggestions.push("\u5148\u770b\u6587\u4ef6\u5934\u5c3e\u548c strings\uff0c\u518d\u51b3\u5b9a\u8fdb\u4e00\u6b65\u5de5\u5177\u3002");
  }

  if (embeddedPayloads.length && artifact.family !== "image") {
    artifact.highlights.push(`\u53d1\u73b0 ${embeddedPayloads.length} \u4e2a\u53ef\u80fd\u7684\u9644\u52a0\u8d44\u6599\u5934\u3002`);
    artifact.suggestions.push("\u68c0\u67e5\u6587\u4ef6\u4e2d\u90e8/\u5c3e\u90e8\u662f\u5426\u5d4c\u5165 ZIP\u3001GZIP\u3001PNG \u6216 PDF\u3002");
    artifact.actions.push({
      id: "extract-appended-payloads",
      label: "\u63d0\u53d6\u9644\u52a0\u8d44\u6599",
    });
  }

  const urls = dedupeStrings(Array.from(searchableText.matchAll(/\bhttps?:\/\/[^\s"'<>]+/gi)).map((match) => match[0]).slice(0, 4));
  if (urls.length) {
    artifact.highlights.push(`\u53d1\u73b0 URL \u7ebf\u7d22 ${urls.length} \u6761\u3002`);
    artifact.keywords.push("http", "url");
  }

  if (artifact.flagCandidates.length) {
    artifact.highlights.unshift(`\u53d1\u73b0 ${artifact.flagCandidates.length} \u4e2a flag \u5019\u9009\u3002`);
  }

  artifact.highlights = dedupeStrings(artifact.highlights).slice(0, 5);
  artifact.suggestions = dedupeStrings(artifact.suggestions).slice(0, 4);
  artifact.keywords = dedupeStrings(artifact.keywords);
  artifact.actions = dedupeStrings(artifact.actions.map((item) => `${item.id}@@${item.label}`)).map((item) => {
    const [id, label] = item.split("@@");
    return { id, label };
  });

  return artifact;
}

function createEmptyScores() {
  return {
    crypto: 0,
    web: 0,
    reverse: 0,
    pwn: 0,
    forensic: 0,
    misc: 0,
  };
}

function classifyChallenge(payload, artifacts) {
  const scores = createEmptyScores();
  const reasons = [];
  const textSource = [
    payload.title || "",
    payload.description || "",
    payload.notes || "",
    ...(payload.tags || []),
    ...artifacts.map((artifact) => `${artifact.name} ${artifact.summary} ${artifact.highlights.join(" ")} ${artifact.keywords.join(" ")}`),
  ]
    .join(" ")
    .toLowerCase();

  for (const [category, words] of Object.entries(CATEGORY_RULES)) {
    let hitCount = 0;
    for (const word of words) {
      if (textSource.includes(word)) {
        scores[category] += 1;
        hitCount += 1;
      }
    }
    if (hitCount) {
      reasons.push(`${COPY.categories[category]} \u547d\u4e2d ${hitCount} \u4e2a\u6587\u672c\u7ebf\u7d22`);
    }
  }

  for (const artifact of artifacts) {
    if (artifact.family === "network") {
      scores.forensic += 3;
      scores.web += 1;
    }
    if (artifact.family === "audio") {
      scores.misc += 2;
      scores.forensic += 1;
    }
    if (artifact.family === "image") {
      scores.misc += 2;
      scores.forensic += 1;
    }
    if (artifact.family === "archive") {
      scores.forensic += 1;
      scores.misc += 1;
    }
    if (artifact.family === "binary") {
      scores.reverse += 2;
      scores.pwn += artifact.badge === "ELF" ? 1 : 0;
    }
    if (artifact.family === "text" && artifact.keywords.includes("base64")) {
      scores.crypto += 1;
      scores.misc += 1;
    }
    if (artifact.flagCandidates.length && artifact.family === "text") {
      scores.misc += 1;
    }
  }

  const ranking = Object.entries(scores).sort((left, right) => right[1] - left[1]);
  const [category, bestScore] = ranking[0];
  const secondScore = ranking[1][1];
  const confidence = bestScore <= 0 ? 0.32 : Math.min(0.96, 0.48 + bestScore * 0.035 + (bestScore - secondScore) * 0.06);

  const evidence = dedupeStrings(reasons.concat(buildEvidenceFromArtifacts(artifacts))).slice(0, 6);

  return {
    id: category,
    label: COPY.categories[category],
    confidence,
    reason:
      evidence[0] ||
      "\u672a\u547d\u4e2d\u5f3a\u7279\u5f81\uff0c\u76ee\u524d\u4ee5\u9644\u4ef6\u5f62\u6001\u548c\u7ebf\u7d22\u5bc6\u5ea6\u505a\u4e3a\u521d\u59cb\u5224\u65ad\u3002",
    evidence,
    summary: COPY.summary[category],
    nextMoves: COPY.nextMoves[category],
    tools: COPY.tools[category],
  };
}

function buildEvidenceFromArtifacts(artifacts) {
  const evidence = [];
  const familyCount = artifacts.reduce((accumulator, artifact) => {
    accumulator[artifact.family] = (accumulator[artifact.family] || 0) + 1;
    return accumulator;
  }, {});

  for (const [family, count] of Object.entries(familyCount)) {
    evidence.push(`${COPY.families[family]} ${count} \u4e2a`);
  }

  artifacts.forEach((artifact) => {
    artifact.highlights.slice(0, 2).forEach((item) => {
      evidence.push(`${artifact.name}: ${item}`);
    });
  });

  return evidence;
}

function buildQuickFindings(artifacts, flagCandidates, pipelineLog) {
  const findings = [];

  if (flagCandidates.length) {
    findings.push(`\u5df2\u63d0\u53d6 ${flagCandidates.length} \u4e2a flag \u5019\u9009\uff0c\u53ef\u4f18\u5148\u4eba\u5de5\u9a8c\u8bc1\u3002`);
  }

  if (pipelineLog.length) {
    findings.push(`\u5df2\u81ea\u52a8\u751f\u6210 ${pipelineLog.length} \u4e2a\u884d\u751f\u7ed3\u679c\uff0c\u5e76\u5bf9\u5176\u4e2d\u7684\u6587\u4ef6\u7ee7\u7eed\u9012\u5f52\u5206\u6790\u3002`);
  }

  const families = artifacts.reduce((accumulator, artifact) => {
    accumulator[artifact.family] = (accumulator[artifact.family] || 0) + 1;
    return accumulator;
  }, {});

  if (families.network) {
    findings.push("\u68c0\u6d4b\u5230\u6d41\u91cf\u9644\u4ef6\uff0c\u5e94\u5f00\u542f HTTP/DNS/TCP \u4f1a\u8bdd\u89c6\u89d2\u3002");
  }
  if (families.image) {
    findings.push("\u68c0\u6d4b\u5230\u56fe\u50cf\u9644\u4ef6\uff0c\u5e94\u52a0\u5165 EXIF\u3001\u50cf\u7d20\u901a\u9053\u548c\u5c3e\u90e8\u9690\u85cf\u6570\u636e\u68c0\u67e5\u3002");
  }
  if (families.audio) {
    findings.push("\u68c0\u6d4b\u5230\u97f3\u9891\u9644\u4ef6\uff0c\u5e94\u68c0\u67e5 RIFF \u5757\u3001PCM LSB\u3001strings \u548c\u6ce2\u5f62\u53ef\u89c6\u5316\u3002");
  }
  if (families.binary) {
    findings.push("\u68c0\u6d4b\u5230\u4e8c\u8fdb\u5236\u9644\u4ef6\uff0c\u5e94\u5148\u62bd strings \u548c\u5bfc\u5165\u8868\u518d\u8fdb\u5165\u9006\u5411\u6216 pwn \u5206\u6790\u3002");
  }
  if (families.archive) {
    findings.push("\u68c0\u6d4b\u5230\u538b\u7f29\u5305\uff0c\u5efa\u8bae\u5c06\u5d4c\u5957\u5185\u5bb9\u4f5c\u4e3a\u65b0\u9898\u6e90\u7ee7\u7eed\u5206\u6790\u3002");
  }

  if (!findings.length) {
    findings.push("\u5148\u6dfb\u52a0\u9644\u4ef6\u6216\u8865\u5145\u66f4\u5177\u4f53\u7684\u63cf\u8ff0\uff0c\u518d\u8ba9\u5de5\u4f5c\u53f0\u7ed9\u51fa\u66f4\u7cbe\u786e\u7684\u5206\u6d41\u3002");
  }

  return findings;
}

function collectPaths(entries, maxFiles = MAX_FILES) {
  const unique = new Set();
  const files = [];
  let truncated = false;

  function walk(entryPath) {
    if (files.length >= maxFiles) {
      truncated = true;
      return;
    }
    if (!entryPath || unique.has(entryPath) || !fs.existsSync(entryPath)) {
      return;
    }
    unique.add(entryPath);

    const stat = fs.statSync(entryPath);
    if (stat.isDirectory()) {
      for (const child of fs.readdirSync(entryPath)) {
        walk(path.join(entryPath, child));
        if (files.length >= maxFiles) {
          truncated = true;
          break;
        }
      }
      return;
    }

    files.push(entryPath);
  }

  entries.forEach((entry) => walk(entry));
  return { files, truncated };
}

function prepareArtifactsFromEntries(entries) {
  const collection = collectPaths(entries);
  return collection.files.map((filePath) => {
    const stat = fs.statSync(filePath);
    const descriptor = detectFamily(filePath, readSample(filePath, Math.min(MAX_SAMPLE_BYTES, 64 * 1024)).buffer);
    return {
      id: filePath,
      path: filePath,
      name: path.basename(filePath),
      family: descriptor.family,
      familyLabel: COPY.families[descriptor.family],
      badge: descriptor.badge,
      sizeLabel: formatBytes(stat.size),
    };
  });
}

function ensureOutputRoot(outputRoot) {
  fs.mkdirSync(outputRoot, { recursive: true });
}

function writeGeneratedFile(outputRoot, fileName, content) {
  ensureOutputRoot(outputRoot);
  const finalPath = path.join(outputRoot, fileName);
  fs.writeFileSync(finalPath, content);
  return finalPath;
}

function buildGeneratedDescriptor(filePath) {
  const stat = fs.statSync(filePath);
  const descriptor = detectFamily(filePath, readSample(filePath, Math.min(MAX_SAMPLE_BYTES, 64 * 1024)).buffer);
  return {
    path: filePath,
    name: path.basename(filePath),
    family: descriptor.family,
    familyLabel: COPY.families[descriptor.family],
    badge: descriptor.badge,
    sizeLabel: formatBytes(stat.size),
    sourceKind: "generated",
  };
}

function createActionOutputRoot(outputRoot, filePath, actionId) {
  return path.join(outputRoot, `${sanitizeSegment(path.parse(filePath).name)}-${shortHash(filePath)}-${actionId}`);
}

function extractAppendedZip(filePath, outputRoot) {
  const buffer = fs.readFileSync(filePath);
  const offset = markerAfterOffset(buffer, Buffer.from([0x50, 0x4b, 0x03, 0x04]), 128);
  if (offset === -1) {
    throw new Error("\u6ca1\u6709\u627e\u5230\u53ef\u63d0\u53d6\u7684 ZIP \u5934\u3002");
  }

  const generatedName = `${sanitizeSegment(path.parse(filePath).name)}-embedded.zip`;
  const outPath = writeGeneratedFile(outputRoot, generatedName, buffer.subarray(offset));
  return {
    message: "\u5df2\u4ece\u56fe\u50cf\u5c3e\u90e8\u63d0\u53d6 ZIP \u9644\u52a0\u6570\u636e\u3002",
    createdFiles: [outPath],
  };
}

function extractAppendedPayloads(filePath, outputRoot) {
  const buffer = fs.readFileSync(filePath);
  const payloads = detectEmbeddedPayloads(buffer, 64).filter((item) => item.offset > 0);
  if (!payloads.length) {
    throw new Error("\u6ca1\u6709\u627e\u5230\u53ef\u63d0\u53d6\u7684\u9644\u52a0\u8d44\u6599\u5934\u3002");
  }

  ensureOutputRoot(outputRoot);
  const createdFiles = [];

  payloads.forEach((payload, index) => {
    const generatedName = `${index + 1}-${payload.id}${payload.ext}`;
    const outPath = writeGeneratedFile(outputRoot, generatedName, buffer.subarray(payload.offset));
    createdFiles.push(outPath);
  });

  return {
    message: "\u5df2\u63d0\u53d6\u9644\u52a0\u8d44\u6599\u5e76\u7ee7\u7eed\u7eb3\u5165\u5206\u6790\u3002",
    createdFiles,
  };
}

function extractArchive(filePath, outputRoot) {
  const sample = readSample(filePath, 16).buffer;
  if (detectMagic(sample) === "gzip" || path.extname(filePath).toLowerCase() === ".gz") {
    const buffer = fs.readFileSync(filePath);
    const inflated = zlib.gunzipSync(buffer, { maxOutputLength: MAX_ARCHIVE_TOTAL_BYTES });
    const parsed = path.parse(filePath);
    let generatedName = sanitizeSegment(parsed.name) || `${sanitizeSegment(parsed.base)}-inflated`;
    if (!path.extname(generatedName)) {
      generatedName = `${generatedName}.bin`;
    }
    const outPath = writeGeneratedFile(outputRoot, generatedName, inflated);
    return {
      message: "\u5df2\u89e3\u538b GZIP \u5e76\u7ee7\u7eed\u7eb3\u5165\u5206\u6790\u3002",
      createdFiles: [outPath],
    };
  }

  const zip = new AdmZip(filePath);
  const entries = zip.getEntries().filter((entry) => !entry.isDirectory);
  if (!entries.length) {
    throw new Error("\u538b\u7f29\u5305\u4e2d\u6ca1\u6709\u53ef\u63d0\u53d6\u7684\u6587\u4ef6\u3002");
  }

  ensureOutputRoot(outputRoot);
  let totalBytes = 0;
  const createdFiles = [];

  for (const entry of entries.slice(0, MAX_ARCHIVE_ENTRIES)) {
    totalBytes += entry.header.size || 0;
    if (totalBytes > MAX_ARCHIVE_TOTAL_BYTES) {
      break;
    }

    const relativePath = safeArchivePath(entry.entryName);
    if (!relativePath) {
      continue;
    }
    const finalPath = path.join(outputRoot, relativePath);
    ensureOutputRoot(path.dirname(finalPath));
    fs.writeFileSync(finalPath, entry.getData());
    createdFiles.push(finalPath);
  }

  if (!createdFiles.length) {
    throw new Error("\u538b\u7f29\u5305\u89e3\u5305\u7ed3\u679c\u4e3a\u7a7a\u6216\u88ab\u9650\u5236\u89c4\u5219\u8fc7\u6ee4\u3002");
  }

  return {
    message: "\u5df2\u89e3\u5305 ZIP \u5e76\u5c06\u5185\u5bb9\u7eb3\u5165\u7ee7\u7eed\u5206\u6790\u3002",
    createdFiles,
  };
}

function decodeEncodedText(filePath, outputRoot) {
  const buffer = fs.readFileSync(filePath);
  const decoded = smartDecodeTextContent(buffer);

  if (!decoded.length) {
    throw new Error("\u6ca1\u6709\u627e\u5230\u53ef\u76f4\u63a5\u89e3\u7801\u7684 Base64 / Hex / XOR / ROT13 / Base32 \u6bb5\u3002");
  }

  const sections = decoded.map((item, index) => {
    return `# ${item.label || item.type.toUpperCase()} ${index + 1}\n${item.value}\n`;
  });
  const generatedName = `${sanitizeSegment(path.parse(filePath).name)}-decoded.txt`;
  const outPath = writeGeneratedFile(outputRoot, generatedName, sections.join("\n"));
  return {
    message: "\u5df2\u5c06\u89e3\u7801\u5185\u5bb9\u8f93\u51fa\u4e3a\u6587\u672c\u6587\u4ef6\u3002",
    createdFiles: [outPath],
  };
}

function exportStrings(filePath, outputRoot) {
  const buffer = fs.readFileSync(filePath);
  const asciiStrings = extractAsciiStrings(buffer, 4, 10000);
  const unicodeStrings = extractUnicodeStrings(buffer, 4, 4000);
  if (!asciiStrings.length && !unicodeStrings.length) {
    throw new Error("\u6ca1\u6709\u63d0\u53d6\u5230\u53ef\u7528 strings\u3002");
  }

  const sections = [];
  if (asciiStrings.length) {
    sections.push("# ASCII", ...asciiStrings, "");
  }
  if (unicodeStrings.length) {
    sections.push("# UTF16-LE", ...unicodeStrings, "");
  }

  const generatedName = `${sanitizeSegment(path.parse(filePath).name)}-strings.txt`;
  const outPath = writeGeneratedFile(outputRoot, generatedName, `${sections.join("\n")}\n`);
  return {
    message: "\u5df2\u5bfc\u51fa ASCII / UTF-16 strings \u7ed3\u679c\u3002",
    createdFiles: [outPath],
  };
}

function extractTrafficSessions(filePath, outputRoot) {
  const buffer = fs.readFileSync(filePath);
  const limited = buffer.length > MAX_TRAFFIC_BYTES ? buffer.subarray(0, MAX_TRAFFIC_BYTES) : buffer;
  const summary = analyzeTrafficBuffer(limited);
  if (!summary.frameCount) {
    throw new Error("\u6ca1\u6709\u4ece pcap/pcapng \u4e2d\u89e3\u6790\u5230\u53ef\u7528\u7684\u6570\u636e\u5e27\u3002");
  }

  ensureOutputRoot(outputRoot);
  const createdFiles = [];
  const summaryName = `${sanitizeSegment(path.parse(filePath).name)}-traffic-summary.txt`;
  const summaryPath = writeGeneratedFile(outputRoot, summaryName, buildTrafficSummaryText(path.basename(filePath), summary));
  createdFiles.push(summaryPath);

  summary.exportedObjects.slice(0, MAX_HTTP_OBJECTS).forEach((item) => {
    createdFiles.push(writeGeneratedFile(outputRoot, item.name, item.content));
  });

  return {
    message: "\u5df2\u63d0\u53d6 HTTP / DNS / TLS / \u4f1a\u8bdd\u7ebf\u7d22\uff0c\u5e76\u5bfc\u51fa\u53ef\u7ee7\u7eed\u5206\u6790\u7684\u5bf9\u8c61\u3002",
    createdFiles,
  };
}

function extractImageQr(filePath, outputRoot) {
  const buffer = fs.readFileSync(filePath);
  const payload = detectQrPayload(buffer);
  if (!payload) {
    throw new Error("\u6ca1\u6709\u4ece\u56fe\u50cf\u4e2d\u89e3\u6790\u5230\u4e8c\u7ef4\u7801\u5185\u5bb9\u3002");
  }

  const outPath = writeGeneratedFile(
    outputRoot,
    `${sanitizeSegment(path.parse(filePath).name)}-qr.txt`,
    `${payload}\n`,
  );
  return {
    message: "\u5df2\u63d0\u53d6\u4e8c\u7ef4\u7801\u5185\u5bb9\u5e76\u7ee7\u7eed\u7eb3\u5165\u5206\u6790\u3002",
    createdFiles: [outPath],
  };
}

async function extractImageBarcode(filePath, outputRoot) {
  const payload = await detectBarcodePayload(filePath);
  if (!payload) {
    throw new Error("\u6ca1\u6709\u4ece\u56fe\u50cf\u4e2d\u89e3\u6790\u5230\u6761\u7801\u5185\u5bb9\u3002");
  }

  const outPath = writeGeneratedFile(
    outputRoot,
    `${sanitizeSegment(path.parse(filePath).name)}-barcode.txt`,
    `${payload}\n`,
  );
  return {
    message: "\u5df2\u63d0\u53d6\u4e00\u7ef4\u6761\u7801\u5185\u5bb9\u5e76\u7ee7\u7eed\u7eb3\u5165\u5206\u6790\u3002",
    createdFiles: [outPath],
  };
}

function buildLumaArray(raster) {
  const values = new Uint8Array(raster.width * raster.height);
  for (let index = 0; index < values.length; index += 1) {
    const offset = index * 4;
    values[index] = Math.round(0.299 * raster.data[offset] + 0.587 * raster.data[offset + 1] + 0.114 * raster.data[offset + 2]);
  }
  return values;
}

function renderEdgeMap(raster) {
  const luma = buildLumaArray(raster);
  return makeGrayPng(raster.width, raster.height, (offset) => {
    const pixel = offset / 4;
    const x = pixel % raster.width;
    const y = Math.floor(pixel / raster.width);
    const center = luma[pixel];
    const right = x + 1 < raster.width ? luma[pixel + 1] : center;
    const down = y + 1 < raster.height ? luma[pixel + raster.width] : center;
    const edge = Math.min(255, Math.abs(center - right) * 4 + Math.abs(center - down) * 4);
    return edge;
  });
}

function renderJpegBlockMap(raster) {
  const luma = buildLumaArray(raster);
  return makeGrayPng(raster.width, raster.height, (offset) => {
    const pixel = offset / 4;
    const x = pixel % raster.width;
    const y = Math.floor(pixel / raster.width);
    let score = 0;
    if (x > 0 && x % 8 === 0) {
      score += Math.abs(luma[pixel] - luma[pixel - 1]) * 8;
    }
    if (y > 0 && y % 8 === 0) {
      score += Math.abs(luma[pixel] - luma[pixel - raster.width]) * 8;
    }
    return Math.min(255, score);
  });
}

function extractImageViews(filePath, outputRoot) {
  const buffer = fs.readFileSync(filePath);
  const raster = decodeImageRaster(buffer);
  if (!raster) {
    throw new Error("\u76ee\u524d\u53ea\u652f\u6301 PNG / JPEG \u7684\u901a\u9053\u5bfc\u51fa\u3002");
  }

  ensureOutputRoot(outputRoot);
  const createdFiles = [];
  const baseName = sanitizeSegment(path.parse(filePath).name);
  const { width, height, data } = raster;

  const channels = [
    { name: "red", index: 0, enabled: true },
    { name: "green", index: 1, enabled: true },
    { name: "blue", index: 2, enabled: true },
    { name: "alpha", index: 3, enabled: data.some((_, idx) => idx % 4 === 3 && data[idx] !== 255) },
  ].filter((item) => item.enabled);

  channels.forEach((channel) => {
    const pngBuffer = makeGrayPng(width, height, (offset) => data[offset + channel.index]);
    createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-${channel.name}.png`, pngBuffer));
  });

  [0, 1, 2, 3].forEach((bitPlane) => {
    const pngBuffer = makeGrayPng(width, height, (offset) => {
      const r = data[offset];
      const g = data[offset + 1];
      const b = data[offset + 2];
      const luminance = Math.round(0.299 * r + 0.587 * g + 0.114 * b);
      return ((luminance >> bitPlane) & 1) * 255;
    });
    createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-luma-bit${bitPlane}.png`, pngBuffer));
  });

  const inversePng = makeGrayPng(width, height, (offset) => {
    const r = data[offset];
    const g = data[offset + 1];
    const b = data[offset + 2];
    const luminance = Math.round(0.299 * r + 0.587 * g + 0.114 * b);
    return 255 - luminance;
  });
  createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-inverse-luma.png`, inversePng));
  createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-edges.png`, renderEdgeMap(raster)));
  if (raster.format === "jpeg") {
    createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-jpeg-blocks.png`, renderJpegBlockMap(raster)));
  }

  return {
    message: "\u5df2\u5bfc\u51fa RGB/\u4eae\u5ea6\u901a\u9053\u3001\u66f4\u591a\u4f4e\u4f4d\u5e73\u9762\u3001\u8fb9\u7f18\u56fe\u548c JPEG \u5757\u6548\u5e94\u89c6\u56fe\u3002",
    createdFiles,
  };
}

function buildAudioSummaryText(fileName, wavInfo, lsbCandidates) {
  const lines = [`# AUDIO SUMMARY`, `file: ${fileName}`, ""];
  if (wavInfo) {
    lines.push(`format: ${wavInfo.audioFormat}`);
    lines.push(`channels: ${wavInfo.channels}`);
    lines.push(`sampleRate: ${wavInfo.sampleRate}`);
    lines.push(`bitsPerSample: ${wavInfo.bitsPerSample}`);
    lines.push(`duration: ${wavInfo.durationSeconds.toFixed(2)}s`);
    lines.push("");
    if (wavInfo.chunks.length) {
      lines.push("# CHUNKS");
      wavInfo.chunks.forEach((chunk) => lines.push(`${chunk.id} ${chunk.size}`));
      lines.push("");
    }
    const metadataEntries = Object.entries(wavInfo.metadata || {});
    if (metadataEntries.length) {
      lines.push("# METADATA");
      metadataEntries.forEach(([key, value]) => lines.push(`${key}: ${value}`));
      lines.push("");
    }
  }
  if (lsbCandidates.length) {
    lines.push("# LSB");
    lsbCandidates.forEach((item) => {
      lines.push(item.channel);
      item.flags.forEach((flag) => lines.push(flag.value));
      item.printable.forEach((entry) => lines.push(entry));
      lines.push("");
    });
  }
  return `${lines.join("\n")}\n`;
}

function extractAudioClues(filePath, outputRoot) {
  const buffer = fs.readFileSync(filePath);
  const wavInfo = parseWavBuffer(buffer);
  const lsbCandidates = wavInfo ? collectAudioLSBCandidates(buffer, wavInfo) : [];
  const strings = dedupeStrings(extractAsciiStrings(buffer, 6, 1200).concat(extractUnicodeStrings(buffer, 6, 400)));

  if (!wavInfo && !lsbCandidates.length && !strings.length) {
    throw new Error("\u6ca1\u6709\u4ece\u97f3\u9891\u9644\u4ef6\u4e2d\u63d0\u53d6\u5230\u9ad8\u4fe1\u53f7\u7ebf\u7d22\u3002");
  }

  ensureOutputRoot(outputRoot);
  const createdFiles = [];
  const baseName = sanitizeSegment(path.parse(filePath).name);
  createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-audio-summary.txt`, buildAudioSummaryText(path.basename(filePath), wavInfo, lsbCandidates)));
  if (lsbCandidates.length) {
    const sections = lsbCandidates.flatMap((item) => {
      const lines = [`# ${item.channel}`];
      item.flags.forEach((flag) => lines.push(flag.value));
      item.printable.forEach((entry) => lines.push(entry));
      lines.push("");
      return lines;
    });
    createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-audio-lsb.txt`, `${sections.join("\n")}\n`));
  }
  if (strings.length) {
    createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-audio-strings.txt`, `${strings.join("\n")}\n`));
  }

  return {
    message: "\u5df2\u63d0\u53d6 WAV \u5757\u4fe1\u606f\u3001strings \u548c PCM LSB \u5019\u9009\u3002",
    createdFiles: dedupeStrings(createdFiles),
  };
}

function extractAudioViews(filePath, outputRoot) {
  const buffer = fs.readFileSync(filePath);
  const wavInfo = parseWavBuffer(buffer);
  if (!wavInfo) {
    throw new Error("\u76ee\u524d\u53ea\u652f\u6301 WAV \u97f3\u9891\u7684\u6ce2\u5f62\u89c6\u56fe\u5bfc\u51fa\u3002");
  }
  const waveform = renderWavWaveform(buffer, wavInfo);
  if (!waveform) {
    throw new Error("\u6ca1\u6709\u751f\u6210 WAV \u6ce2\u5f62\u56fe\u3002");
  }

  const outPath = writeGeneratedFile(outputRoot, `${sanitizeSegment(path.parse(filePath).name)}-waveform.png`, waveform);
  return {
    message: "\u5df2\u5bfc\u51fa WAV \u6ce2\u5f62\u56fe\u3002",
    createdFiles: [outPath],
  };
}

function extractPdfContent(filePath, outputRoot) {
  const buffer = fs.readFileSync(filePath);
  const report = analyzePdfBuffer(buffer);
  if (!report) {
    throw new Error("\u4e0d\u662f\u53ef\u89e3\u6790\u7684 PDF \u6587\u6863\u3002");
  }

  const hasContent =
    Object.keys(report.metadata || {}).length || report.urls.length || report.xmpPackets.length || report.extractedStreams.length;
  if (!hasContent) {
    throw new Error("\u6ca1\u6709\u4ece PDF \u4e2d\u63d0\u53d6\u5230\u9ad8\u4fe1\u53f7\u5185\u5bb9\u3002");
  }

  ensureOutputRoot(outputRoot);
  const createdFiles = [];
  const baseName = sanitizeSegment(path.parse(filePath).name);
  createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-pdf-summary.txt`, buildPdfSummaryText(path.basename(filePath), report)));

  report.xmpPackets.forEach((packet, index) => {
    createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-xmp-${index + 1}.xml`, packet));
  });

  report.extractedStreams.forEach((stream) => {
    createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-pdf-stream-${stream.index}.txt`, `${stream.text}\n`));
  });

  return {
    message: "\u5df2\u63d0\u53d6 PDF \u5143\u6570\u636e\u3001XMP\u3001stream \u548c URL \u7ebf\u7d22\u3002",
    createdFiles: dedupeStrings(createdFiles),
  };
}

function extractDocumentPackage(filePath, outputRoot) {
  return extractArchive(filePath, outputRoot);
}

function extractJpegComments(buffer) {
  if (detectMagic(buffer) !== "jpeg" || buffer.length < 4) {
    return [];
  }

  const comments = [];
  let offset = 2;

  while (offset + 4 <= buffer.length) {
    if (buffer[offset] !== 0xff) {
      offset += 1;
      continue;
    }

    const marker = buffer[offset + 1];
    offset += 2;

    if (marker === 0xd9 || marker === 0xda) {
      break;
    }
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
      continue;
    }
    if (offset + 2 > buffer.length) {
      break;
    }

    const length = buffer.readUInt16BE(offset);
    if (length < 2 || offset + length > buffer.length) {
      break;
    }

    const data = buffer.subarray(offset + 2, offset + length);
    if (marker === 0xfe) {
      const text = decodeBufferAsText(data).trim();
      if (text) {
        comments.push(text);
      }
    } else if (marker === 0xe1 || marker === 0xe2) {
      extractPrintableSegments(decodeBufferAsText(data), 8, 10).forEach((item) => comments.push(item));
    }

    offset += length;
  }

  return dedupeStrings(comments).slice(0, 40);
}

function getJpegMarkerName(marker) {
  if (marker === 0xda) {
    return "SOS";
  }
  if (marker === 0xd9) {
    return "EOI";
  }
  if (marker === 0xfe) {
    return "COM";
  }
  if (marker >= 0xe0 && marker <= 0xef) {
    return `APP${marker - 0xe0}`;
  }
  if (marker >= 0xc0 && marker <= 0xcf) {
    return `SOF${marker - 0xc0}`;
  }
  return `0x${marker.toString(16).padStart(2, "0").toUpperCase()}`;
}

function identifyJpegSegmentKind(marker, data) {
  if (marker === 0xfe) {
    return "comment";
  }
  if (marker === 0xe0 && data.subarray(0, 5).toString("ascii") === "JFIF\0") {
    return "jfif";
  }
  if (marker === 0xe1 && data.subarray(0, 6).toString("ascii") === "Exif\0\0") {
    return "exif";
  }
  if (marker === 0xe1 && data.subarray(0, 29).toString("utf8").startsWith("http://ns.adobe.com/xap/1.0/")) {
    return "xmp";
  }
  if (marker === 0xe2 && data.subarray(0, 12).toString("ascii") === "ICC_PROFILE\0") {
    return "icc";
  }
  if (marker === 0xed && data.subarray(0, 13).toString("ascii") === "Photoshop 3.0") {
    return "photoshop";
  }
  if (marker === 0xee && data.subarray(0, 5).toString("ascii") === "Adobe") {
    return "adobe";
  }
  return "segment";
}

function parseJpegSegments(buffer) {
  if (detectMagic(buffer) !== "jpeg" || buffer.length < 4) {
    return [];
  }

  const segments = [];
  let offset = 2;

  while (offset + 4 <= buffer.length) {
    while (offset < buffer.length && buffer[offset] === 0xff) {
      offset += 1;
    }
    if (offset >= buffer.length) {
      break;
    }

    const marker = buffer[offset];
    offset += 1;

    if (marker === 0xd9) {
      break;
    }
    if (marker === 0xda) {
      break;
    }
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
      continue;
    }
    if (offset + 2 > buffer.length) {
      break;
    }

    const length = buffer.readUInt16BE(offset);
    if (length < 2 || offset + length > buffer.length) {
      break;
    }

    const data = buffer.subarray(offset + 2, offset + length);
    const markerName = getJpegMarkerName(marker);
    const kind = identifyJpegSegmentKind(marker, data);
    segments.push({
      marker,
      markerName,
      kind,
      offset: offset - 1,
      size: data.length,
      data,
    });

    offset += length;
  }

  return segments;
}

function segmentPreviewText(segment) {
  if (segment.kind === "comment") {
    return decodeBufferAsText(segment.data).trim();
  }
  if (segment.kind === "xmp") {
    const zero = segment.data.indexOf(0);
    const payload = zero === -1 ? segment.data : segment.data.subarray(zero + 1);
    return decodeBufferAsText(payload).trim();
  }
  return extractPrintableSegments(decodeBufferAsText(segment.data), 8, 8).join(" | ");
}

function buildJpegSegmentSummary(segments, fileName) {
  const lines = [`# JPEG SEGMENTS`, `file: ${fileName}`, `count: ${segments.length}`, ""];
  segments.forEach((segment, index) => {
    lines.push(
      `[${String(index + 1).padStart(2, "0")}] ${segment.markerName} kind=${segment.kind} offset=${segment.offset} size=${segment.size}`,
    );
    const preview = segmentPreviewText(segment);
    if (preview) {
      lines.push(preview);
    }
    lines.push("");
  });
  return `${lines.join("\n")}\n`;
}

function extractJpegSegments(filePath, outputRoot) {
  const buffer = fs.readFileSync(filePath);
  const segments = parseJpegSegments(buffer);
  if (!segments.length) {
    throw new Error("\u6ca1\u6709\u63d0\u53d6\u5230\u53ef\u7528\u7684 JPEG \u6bb5\u3002");
  }

  ensureOutputRoot(outputRoot);
  const createdFiles = [];
  const summaryName = `${sanitizeSegment(path.parse(filePath).name)}-jpeg-segments.txt`;
  createdFiles.push(writeGeneratedFile(outputRoot, summaryName, buildJpegSegmentSummary(segments, path.basename(filePath))));

  segments.forEach((segment, index) => {
    const prefix = `${String(index + 1).padStart(2, "0")}-${segment.markerName.toLowerCase()}-${segment.kind}`;
    if (segment.kind === "comment") {
      const text = decodeBufferAsText(segment.data).trim();
      if (text) {
        createdFiles.push(writeGeneratedFile(outputRoot, `${prefix}.txt`, `${text}\n`));
      }
      return;
    }

    if (segment.kind === "xmp") {
      const zero = segment.data.indexOf(0);
      const payload = zero === -1 ? segment.data : segment.data.subarray(zero + 1);
      if (payload.length) {
        createdFiles.push(writeGeneratedFile(outputRoot, `${prefix}.xml`, payload));
      }
      return;
    }

    if (segment.kind === "icc") {
      const headerLength = 14;
      const payload = segment.data.length > headerLength ? segment.data.subarray(headerLength) : segment.data;
      createdFiles.push(writeGeneratedFile(outputRoot, `${prefix}.icc`, payload));
      return;
    }

    if (segment.kind === "exif") {
      const payload = segment.data.length > 6 ? segment.data.subarray(6) : segment.data;
      createdFiles.push(writeGeneratedFile(outputRoot, `${prefix}.exif.bin`, payload));
      const preview = extractPrintableSegments(decodeBufferAsText(payload), 8, 20);
      if (preview.length) {
        createdFiles.push(writeGeneratedFile(outputRoot, `${prefix}.txt`, `${preview.join("\n")}\n`));
      }
      return;
    }

    const printable = extractPrintableSegments(decodeBufferAsText(segment.data), 8, 20);
    if (printable.length) {
      createdFiles.push(writeGeneratedFile(outputRoot, `${prefix}.txt`, `${printable.join("\n")}\n`));
    } else if (["photoshop", "adobe", "segment"].includes(segment.kind) && segment.data.length) {
      createdFiles.push(writeGeneratedFile(outputRoot, `${prefix}.bin`, segment.data));
    }
  });

  return {
    message: "\u5df2\u62c6\u51fa JPEG \u6bb5\u3001\u6ce8\u91ca\u548c APP \u5185\u5bb9\uff0c\u5e76\u7ee7\u7eed\u7eb3\u5165\u5206\u6790\u3002",
    createdFiles: dedupeStrings(createdFiles),
  };
}

function extractImageMetadata(filePath, outputRoot) {
  const buffer = fs.readFileSync(filePath);
  const lines = [];
  try {
    const metadata = ExifParser.create(buffer).parse();
    Object.entries(metadata.tags || {}).forEach(([key, value]) => {
      lines.push(`${key}: ${value}`);
    });
  } catch (_error) {
    // ignore
  }

  const strings = extractAsciiStrings(buffer, 6, 500);
  const comments = strings.filter((value) => /flag|comment|author|software|icc|photoshop|adobe/i.test(value)).slice(0, 40);
  comments.forEach((value) => lines.push(value));
  extractJpegComments(buffer).forEach((value) => lines.push(value));

  if (!lines.length) {
    throw new Error("\u6ca1\u6709\u63d0\u53d6\u5230\u660e\u663e\u7684\u56fe\u50cf\u5143\u6570\u636e\u6216\u6ce8\u91ca\u5185\u5bb9\u3002");
  }

  const generatedName = `${sanitizeSegment(path.parse(filePath).name)}-metadata.txt`;
  const outPath = writeGeneratedFile(outputRoot, generatedName, `${lines.join("\n")}\n`);
  return {
    message: "\u5df2\u63d0\u53d6\u56fe\u50cf\u5143\u6570\u636e\u548c\u53ef\u7591\u6ce8\u91ca\u6587\u672c\u3002",
    createdFiles: [outPath],
  };
}

function extractPngText(filePath, outputRoot) {
  const buffer = fs.readFileSync(filePath);
  const chunks = extractPngTextChunks(buffer);
  if (!chunks.length) {
    throw new Error("\u6ca1\u6709\u63d0\u53d6\u5230 PNG \u6587\u672c\u5757\u3002");
  }

  const generatedName = `${sanitizeSegment(path.parse(filePath).name)}-png-text.txt`;
  const outPath = writeGeneratedFile(outputRoot, generatedName, `${chunks.join("\n")}\n`);
  return {
    message: "\u5df2\u63d0\u53d6 PNG \u6587\u672c\u5757\u3002",
    createdFiles: [outPath],
  };
}

function extractPngLsb(filePath, outputRoot) {
  const buffer = fs.readFileSync(filePath);
  const candidates = collectPngLSBCandidates(buffer);
  if (!candidates.length) {
    throw new Error("\u6ca1\u6709\u63d0\u53d6\u5230\u53ef\u7528\u7684 PNG \u4f4e\u4f4d\u5e73\u9762\u6587\u672c\u5019\u9009\u3002");
  }

  const sections = candidates.flatMap((item) => {
    const lines = [`# ${item.traversal.toUpperCase()} ${item.channel} bit${item.bitPlane} ${item.bitOrder.toUpperCase()}`];
    item.printable.forEach((entry) => lines.push(entry));
    item.flags.forEach((entry) => lines.push(entry.value));
    lines.push("");
    return lines;
  });
  const generatedName = `${sanitizeSegment(path.parse(filePath).name)}-png-lsb.txt`;
  const outPath = writeGeneratedFile(outputRoot, generatedName, `${sections.join("\n")}\n`);
  return {
    message: "\u5df2\u5bfc\u51fa PNG \u4f4e\u4f4d\u5e73\u9762\u5019\u9009\u6587\u672c\u3002",
    createdFiles: [outPath],
  };
}

async function runArtifactActionInternal(actionId, filePath, outputRoot) {
  if (!filePath || !fs.existsSync(filePath)) {
    throw new Error("\u76ee\u6807\u9644\u4ef6\u4e0d\u5b58\u5728\u3002");
  }

  const baseDir = createActionOutputRoot(outputRoot, filePath, actionId);

  if (actionId === "extract-appended-zip" || actionId === "extract-appended-payloads") {
    return actionId === "extract-appended-zip" ? extractAppendedZip(filePath, baseDir) : extractAppendedPayloads(filePath, baseDir);
  }
  if (actionId === "extract-archive") {
    return extractArchive(filePath, baseDir);
  }
  if (actionId === "extract-image-metadata") {
    return extractImageMetadata(filePath, baseDir);
  }
  if (actionId === "extract-jpeg-segments") {
    return extractJpegSegments(filePath, baseDir);
  }
  if (actionId === "extract-image-qr") {
    return extractImageQr(filePath, baseDir);
  }
  if (actionId === "extract-image-barcode") {
    return extractImageBarcode(filePath, baseDir);
  }
  if (actionId === "extract-image-views") {
    return extractImageViews(filePath, baseDir);
  }
  if (actionId === "extract-audio-clues") {
    return extractAudioClues(filePath, baseDir);
  }
  if (actionId === "extract-audio-views") {
    return extractAudioViews(filePath, baseDir);
  }
  if (actionId === "extract-pdf-content") {
    return extractPdfContent(filePath, baseDir);
  }
  if (actionId === "extract-document-package") {
    return extractDocumentPackage(filePath, baseDir);
  }
  if (actionId === "decode-encoded-text") {
    return decodeEncodedText(filePath, baseDir);
  }
  if (actionId === "extract-traffic-sessions") {
    return extractTrafficSessions(filePath, baseDir);
  }
  if (actionId === "extract-strings") {
    return exportStrings(filePath, baseDir);
  }
  if (actionId === "extract-png-text") {
    return extractPngText(filePath, baseDir);
  }
  if (actionId === "extract-png-lsb") {
    return extractPngLsb(filePath, baseDir);
  }

  throw new Error(`Unsupported action: ${actionId}`);
}

function shouldAutoRun(actionId, artifact) {
  if (actionId === "extract-appended-zip" || actionId === "extract-appended-payloads") {
    return true;
  }
  if (actionId === "extract-archive") {
    return artifact.depth < MAX_PIPELINE_DEPTH;
  }
  if (actionId === "extract-image-metadata") {
    return artifact.depth === 0;
  }
  if (actionId === "extract-jpeg-segments") {
    return artifact.badge === "JPEG" && artifact.depth === 0;
  }
  if (actionId === "extract-image-qr") {
    return artifact.family === "image" && artifact.depth === 0;
  }
  if (actionId === "extract-image-barcode") {
    return artifact.family === "image" && artifact.depth === 0;
  }
  if (actionId === "extract-image-views") {
    return false;
  }
  if (actionId === "extract-audio-clues") {
    return artifact.family === "audio" && artifact.depth === 0;
  }
  if (actionId === "extract-audio-views") {
    return false;
  }
  if (actionId === "extract-pdf-content") {
    return artifact.badge === "PDF" && artifact.depth === 0;
  }
  if (actionId === "extract-document-package") {
    return artifact.family === "document" && isOfficePackageExtension(artifact.extension) && artifact.depth < MAX_PIPELINE_DEPTH;
  }
  if (actionId === "decode-encoded-text") {
    return artifact.depth < MAX_PIPELINE_DEPTH;
  }
  if (actionId === "extract-traffic-sessions") {
    return artifact.family === "network" && artifact.depth === 0;
  }
  if (actionId === "extract-strings") {
    return artifact.family === "binary" || artifact.family === "network";
  }
  if (actionId === "extract-png-text" || actionId === "extract-png-lsb") {
    return artifact.depth < MAX_PIPELINE_DEPTH;
  }
  return false;
}

async function buildPipelineArtifacts(rootPaths, outputRoot) {
  const queue = rootPaths.map((filePath) => ({
    filePath,
    depth: 0,
    sourceKind: "input",
    generatedBy: null,
    parentPath: null,
  }));

  const seen = new Set();
  const artifacts = [];
  const pipelineLog = [];

  while (queue.length && artifacts.length < MAX_FILES) {
    const current = queue.shift();
    if (seen.has(current.filePath) || !fs.existsSync(current.filePath)) {
      continue;
    }
    seen.add(current.filePath);

    const artifact = await buildArtifactSignals(current.filePath);
    artifact.depth = current.depth;
    artifact.sourceKind = current.sourceKind;
    artifact.generatedBy = current.generatedBy;
    artifact.parentPath = current.parentPath;
    artifacts.push(artifact);

    for (const action of artifact.actions || []) {
      if (!shouldAutoRun(action.id, artifact)) {
        continue;
      }
      try {
        const result = await runArtifactActionInternal(action.id, artifact.path, outputRoot);
        const createdArtifacts = result.createdFiles
          .filter((createdPath) => fs.existsSync(createdPath))
          .map((createdPath) => buildGeneratedDescriptor(createdPath));

        if (!createdArtifacts.length) {
          continue;
        }

        pipelineLog.push({
          actionId: action.id,
          actionLabel: action.label,
          sourcePath: artifact.path,
          sourceName: artifact.name,
          message: result.message,
          createdArtifacts,
        });

        createdArtifacts.forEach((created) => {
          queue.push({
            filePath: created.path,
            depth: current.depth + 1,
            sourceKind: "generated",
            generatedBy: action.label,
            parentPath: artifact.path,
          });
        });
      } catch (_error) {
        // optional derivation; ignore failures
      }
    }
  }

  return { artifacts, pipelineLog };
}

async function analyzeChallenge(payload, outputRoot) {
  const title = String(payload.title || "").trim();
  const description = String(payload.description || "").trim();
  const notes = String(payload.notes || "").trim();
  const tags = Array.isArray(payload.tags)
    ? payload.tags.map((item) => String(item).trim()).filter(Boolean)
    : String(payload.tags || "")
        .split(/\s+/)
        .map((item) => item.trim())
        .filter(Boolean);

  if (!title && !description && !notes && (!payload.artifacts || !payload.artifacts.length)) {
    throw new Error("\u8bf7\u81f3\u5c11\u8f93\u5165\u9898\u76ee\u4fe1\u606f\u6216\u6dfb\u52a0\u4e00\u4e2a\u9644\u4ef6\u3002");
  }

  const collection = collectPaths(payload.artifacts || []);
  const pipeline = await buildPipelineArtifacts(collection.files, outputRoot);
  const inlineFlags = [
    ...findFlagCandidates(title, "\u6807\u9898"),
    ...findFlagCandidates(description, "\u63cf\u8ff0"),
    ...findFlagCandidates(notes, "\u8865\u5145\u7ebf\u7d22"),
  ];
  const allFlagCandidates = dedupeStrings(
    inlineFlags
      .concat(pipeline.artifacts.flatMap((artifact) => artifact.flagCandidates))
      .map((item) => `${item.value}@@${item.source}`),
  ).map((entry) => {
    const [value, source] = entry.split("@@");
    return { value, source };
  });

  const classification = classifyChallenge({ title, description, notes, tags }, pipeline.artifacts);
  const quickFindings = buildQuickFindings(pipeline.artifacts, allFlagCandidates, pipeline.pipelineLog);
  const warnings = [];

  if (collection.truncated) {
    warnings.push(COPY.app.truncated);
  }

  return {
    challenge: {
      title: title || COPY.app.unnamed,
      description,
      notes,
      tags,
      artifactCount: pipeline.artifacts.length,
    },
    classification,
    artifacts: pipeline.artifacts,
    pipelineLog: pipeline.pipelineLog,
    quickFindings,
    flagCandidates: allFlagCandidates,
    warnings,
    inferredNeeds: COPY.needs,
    emptyFlagMessage: COPY.app.noFlags,
  };
}

async function runArtifactAction(actionId, filePath, outputRoot) {
  const result = await runArtifactActionInternal(actionId, filePath, outputRoot);

  return {
    message: result.message,
    generatedArtifacts: result.createdFiles.map((createdPath) => ({
      ...buildGeneratedDescriptor(createdPath),
      generatedBy: actionId,
      parentPath: filePath,
    })),
  };
}

module.exports = {
  analyzeChallenge,
  prepareArtifactsFromEntries,
  runArtifactAction,
};
