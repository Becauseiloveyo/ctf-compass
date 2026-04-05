const form = document.getElementById("analyze-form");
const titleInput = document.getElementById("title");
const descriptionInput = document.getElementById("description");
const tagsInput = document.getElementById("tags");
const statusLine = document.getElementById("status");
const emptyState = document.getElementById("empty-state");
const resultView = document.getElementById("result-view");
const categoryName = document.getElementById("category-name");
const confidenceValue = document.getElementById("confidence-value");
const reasonText = document.getElementById("reason-text");
const guideSummary = document.getElementById("guide-summary");
const nextSteps = document.getElementById("next-steps");
const methodChecklist = document.getElementById("method-checklist");
const toolList = document.getElementById("tool-list");
const appMeta = document.getElementById("app-meta");
const langToggle = document.getElementById("lang-toggle");
const themeToggle = document.getElementById("theme-toggle");

const translations = {
  "zh-CN": {
    appTag: "桌面解题工作台",
    appTitle: "CTF Compass",
    heroTag: "统一分析入口",
    heroTitle: "像手机设置一样，直接、清晰、好用。",
    heroCopy: "输入题目标题、描述和标签，应用会给出题型判断、方法指引、工具建议和后续步骤。",
    inputTag: "题目录入",
    inputTitle: "新建分析",
    fieldTitle: "题目标题",
    fieldDescription: "题目描述",
    fieldTags: "标签",
    presetCrypto: "RSA 热身",
    presetWeb: "Web 会话题",
    presetReverse: "混淆二进制",
    analyzeButton: "开始分析",
    statusReady: "已就绪，将通过本地 Python 分析桥执行分类。",
    focusTag: "关注题型",
    focusTitle: "内置方向",
    focusCrypto: "密码分析",
    focusWeb: "Web 解题引导",
    focusReverse: "逆向分析",
    focusPwn: "内存利用",
    focusForensic: "取证排查",
    focusMisc: "杂项归类",
    summaryTag: "分析摘要",
    emptyCategory: "等待分析",
    emptyReason: "运行一次分析后，这里会显示题型判断依据和建议切入点。",
    confidenceLabel: "置信度",
    emptyTitle: "还没有分析结果",
    emptyCopy: "在左侧填写题目信息，应用会返回题型、方法学 checklist 和推荐工具。",
    guideTag: "方法摘要",
    guideTitle: "解题说明",
    stepsTag: "建议步骤",
    stepsTitle: "下一步",
    checklistTag: "方法学清单",
    checklistTitle: "检查项",
    toolsTag: "推荐工具",
    toolsTitle: "可配合使用",
    boundaryTag: "边界说明",
    boundaryTitle: "安全限制",
    boundaryCopy: "本应用面向合法 CTF 训练环境，仅提供题型分类、方法指引和本地分析辅助，不面向真实目标攻击自动化。",
    placeholderTitle: "例如：Ghost Session",
    placeholderDescription: "粘贴题目说明、附件摘要、已有线索、异常行为。",
    placeholderTags: "web auth cookie jwt",
    statusAnalyzing: "正在分析题目...",
    statusDone: "分析完成：{title}",
    statusError: "分析失败：{message}",
    themeLight: "浅色",
    themeDark: "暗色",
  },
  en: {
    appTag: "Desktop Analysis Workspace",
    appTitle: "CTF Compass",
    heroTag: "Unified Intake",
    heroTitle: "Direct, clean, and usable like a phone settings app.",
    heroCopy: "Enter a challenge title, description, and tags. The app returns category guidance, workflow hints, tools, and next steps.",
    inputTag: "Challenge Intake",
    inputTitle: "New Analysis",
    fieldTitle: "Challenge Title",
    fieldDescription: "Description",
    fieldTags: "Tags",
    presetCrypto: "RSA Warmup",
    presetWeb: "Web Session",
    presetReverse: "Obfuscated Binary",
    analyzeButton: "Run Analysis",
    statusReady: "Ready. The local Python bridge will classify the challenge.",
    focusTag: "Focus Areas",
    focusTitle: "Built-in Categories",
    focusCrypto: "Cryptanalysis",
    focusWeb: "Web guidance",
    focusReverse: "Reverse engineering",
    focusPwn: "Memory exploitation",
    focusForensic: "Forensic triage",
    focusMisc: "Misc classification",
    summaryTag: "Summary",
    emptyCategory: "Waiting for analysis",
    emptyReason: "Run one analysis to see the reasoning and the recommended entry point.",
    confidenceLabel: "Confidence",
    emptyTitle: "No result yet",
    emptyCopy: "Fill in the challenge details on the left. The app will return the category, checklist, and suggested tools.",
    guideTag: "Guide Summary",
    guideTitle: "Method Overview",
    stepsTag: "Suggested Steps",
    stepsTitle: "Next Actions",
    checklistTag: "Method Checklist",
    checklistTitle: "Checklist",
    toolsTag: "Suggested Tools",
    toolsTitle: "Recommended Tools",
    boundaryTag: "Boundary",
    boundaryTitle: "Safety Limit",
    boundaryCopy: "This app is for lawful CTF environments only. It provides classification, methodology guidance, and local analysis support, not real-world attack automation.",
    placeholderTitle: "Example: Ghost Session",
    placeholderDescription: "Paste the prompt, file summary, observations, and suspicious behavior.",
    placeholderTags: "web auth cookie jwt",
    statusAnalyzing: "Analyzing challenge...",
    statusDone: "Analysis complete: {title}",
    statusError: "Analysis failed: {message}",
    themeLight: "Light",
    themeDark: "Dark",
  },
};

const presets = {
  crypto: {
    title: {
      "zh-CN": "RSA 热身",
      en: "RSA Warmup",
    },
    description: {
      "zh-CN": "题目给出了 n、e 和密文。恢复明文并说明漏洞点。",
      en: "The challenge gives n, e, and a ciphertext. Recover the plaintext and explain the weakness.",
    },
    tags: "crypto rsa modulus",
  },
  web: {
    title: {
      "zh-CN": "Ghost Session",
      en: "Ghost Session",
    },
    description: {
      "zh-CN": "一个小型站点把管理员判断放在 Cookie 逻辑里。识别可能漏洞类型并梳理路由面。",
      en: "A small challenge site uses cookies for admin logic. Identify the likely flaw class and map the route surface.",
    },
    tags: "web auth cookie session",
  },
  reverse: {
    title: {
      "zh-CN": "混淆保险箱",
      en: "Vault Binary",
    },
    description: {
      "zh-CN": "一个 ELF 二进制要求输入密钥。恢复校验流程并找出关键逻辑。",
      en: "An ELF binary asks for a key. Recover the validation flow and identify the critical logic.",
    },
    tags: "reverse binary elf ghidra",
  },
};

let currentLang = "zh-CN";
let currentTheme = "light";

function t(key) {
  return translations[currentLang][key] || key;
}

function setStatus(message, isError = false) {
  statusLine.textContent = message;
  statusLine.style.color = isError ? "var(--danger)" : "var(--muted)";
}

function renderList(target, items) {
  target.innerHTML = "";
  items.forEach((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    target.appendChild(li);
  });
}

function applyTranslations() {
  document.querySelectorAll("[data-i18n]").forEach((node) => {
    node.textContent = t(node.dataset.i18n);
  });

  titleInput.placeholder = t("placeholderTitle");
  descriptionInput.placeholder = t("placeholderDescription");
  tagsInput.placeholder = t("placeholderTags");
  langToggle.textContent = currentLang === "zh-CN" ? "EN" : "中文";

  const themeLabels = document.querySelectorAll(".theme-switch-label");
  themeLabels[0].textContent = t("themeLight");
  themeLabels[1].textContent = t("themeDark");
}

async function hydrateMeta() {
  try {
    const meta = await window.ctfCompass.getMeta();
    appMeta.textContent = `${meta.mode} | v${meta.version}`;
  } catch (_error) {
    appMeta.textContent = "metadata unavailable";
  }
}

function applyPreset(key) {
  const preset = presets[key];
  titleInput.value = preset.title[currentLang];
  descriptionInput.value = preset.description[currentLang];
  tagsInput.value = preset.tags;
}

function toggleLanguage() {
  currentLang = currentLang === "zh-CN" ? "en" : "zh-CN";
  document.documentElement.lang = currentLang;
  applyTranslations();
  setStatus(t("statusReady"));
}

function toggleTheme() {
  currentTheme = currentTheme === "light" ? "dark" : "light";
  document.body.dataset.theme = currentTheme;
}

document.querySelectorAll(".preset-chip").forEach((button) => {
  button.addEventListener("click", () => {
    applyPreset(button.dataset.preset);
  });
});

langToggle.addEventListener("click", toggleLanguage);
themeToggle.addEventListener("click", toggleTheme);

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  setStatus(t("statusAnalyzing"));

  const payload = {
    title: titleInput.value.trim(),
    description: descriptionInput.value.trim(),
    lang: currentLang,
    tags: tagsInput.value
      .split(/\s+/)
      .map((tag) => tag.trim())
      .filter(Boolean),
  };

  try {
    const result = await window.ctfCompass.analyzeChallenge(payload);
    emptyState.classList.add("hidden");
    resultView.classList.remove("hidden");

    categoryName.textContent = result.guide.label;
    confidenceValue.textContent = result.classification.confidence.toFixed(2);
    reasonText.textContent = result.classification.reason;
    guideSummary.textContent = result.guide.summary;
    renderList(nextSteps, result.classification.nextSteps);
    renderList(methodChecklist, result.guide.checklist);
    renderList(toolList, result.guide.tools);
    setStatus(t("statusDone").replace("{title}", result.challenge.title));
  } catch (error) {
    setStatus(t("statusError").replace("{message}", error.message || "unknown error"), true);
  }
});

applyTranslations();
setStatus(t("statusReady"));
hydrateMeta();
