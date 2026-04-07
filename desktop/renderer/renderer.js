const STRINGS = {
  brandCaption: "\u6311\u6218\u5de5\u4f5c\u53f0",
  navWorkspace: "\u5de5\u4f5c\u53f0",
  navArtifacts: "\u9644\u4ef6",
  navResults: "\u7ed3\u679c",
  navSettings: "\u8bbe\u7f6e",
  themeTitle: "\u4e3b\u9898",
  themeNote: "\u6d45\u8272\u4f18\u5148\uff0c\u4e5f\u53ef\u5207\u6362\u6697\u9ed1",
  runtimeTitle: "\u5f53\u524d\u73af\u5883",
  exportReportButton: "\u5bfc\u51fa\u62a5\u544a",
  addFilesButton: "\u6dfb\u52a0\u6587\u4ef6",
  addFolderButton: "\u6dfb\u52a0\u6587\u4ef6\u5939",
  runAnalysisButton: "\u7acb\u5373\u5206\u6790",
  quickFilesTitle: "\u6dfb\u52a0\u6587\u4ef6",
  quickFilesNote: "\u56fe\u50cf\u3001txt\u3001zip\u3001ELF\u3001pcap \u90fd\u53ef\u4ee5\u76f4\u63a5\u62d6\u8fdb\u6765",
  quickFolderTitle: "\u626b\u63cf\u76ee\u5f55",
  quickFolderNote: "\u9002\u5408\u6709\u591a\u4e2a\u9644\u4ef6\u6216\u5bfc\u51fa\u6587\u4ef6\u7684\u9898\u76ee",
  quickPasteTitle: "\u8865\u5145\u7ebf\u7d22",
  quickPasteNote: "\u628a\u9898\u9762\u3001hint\u3001\u5df2\u6709\u53d1\u73b0\u7c98\u8d34\u8fdb\u6765",
  quickRunTitle: "\u5f00\u59cb\u5206\u6d41",
  quickRunNote: "\u5148\u627e flag \u5019\u9009\uff0c\u518d\u7ed9\u9898\u578b\u8def\u5f84\u548c\u5de5\u5177\u5efa\u8bae",
  workspacePanelKicker: "\u9898\u76ee\u5de5\u4f5c\u53f0",
  workspacePanelTitle: "\u9898\u9762\u4e0e\u7ebf\u7d22",
  workspacePanelBadge: "\u79bb\u7ebf\u672c\u5730",
  fieldTitle: "\u9898\u76ee\u6807\u9898",
  fieldTags: "\u6807\u7b7e",
  fieldDescription: "\u9898\u76ee\u63cf\u8ff0",
  fieldNotes: "\u8865\u5145\u7ebf\u7d22",
  artifactPanelKicker: "\u9644\u4ef6\u8f93\u5165",
  artifactPanelTitle: "\u6587\u4ef6\u8d44\u4ea7",
  dropzoneTitle: "\u62d6\u62fd\u6587\u4ef6\u6216\u70b9\u51fb\u6dfb\u52a0",
  dropzoneNote: "\u56fe\u7247\u3001\u6587\u672c\u3001\u538b\u7f29\u5305\u3001ELF\u3001pcap/pcapng \u4f1a\u88ab\u4f5c\u4e3a\u4e00\u7b49\u8f93\u5165",
  discoveryKicker: "\u81ea\u52a8\u53d1\u73b0",
  discoveryTitle: "\u5f53\u524d\u7ebf\u7d22",
  needsKicker: "\u9700\u6c42\u62c6\u89e3",
  needsTitle: "\u4f60\u771f\u6b63\u9700\u8981\u7684\u80fd\u529b",
  summaryKicker: "\u7ed3\u679c\u6458\u8981",
  pipelineKicker: "\u81ea\u52a8\u5904\u7406",
  pipelineTitle: "\u672c\u5730\u9012\u5f52\u94fe\u8def",
  confidenceLabel: "\u7f6e\u4fe1",
  flagKicker: "FLAG",
  flagTitle: "\u5019\u9009\u503c",
  nextKicker: "\u5206\u6790\u8def\u5f84",
  nextTitle: "\u4e0b\u4e00\u6b65",
  findingKicker: "\u9644\u4ef6\u53d1\u73b0",
  findingTitle: "\u91cd\u70b9\u68c0\u67e5\u9879",
  toolKicker: "\u5de5\u5177\u94fe",
  toolTitle: "\u914d\u5408\u4f7f\u7528",
  settingsKicker: "\u8fd0\u884c\u7b56\u7565",
  settingsTitle: "\u9879\u76ee\u57fa\u7ebf",
  settingsThemeTitle: "\u754c\u9762\u98ce\u683c",
  settingsThemeNote: "\u9ed8\u8ba4\u767d\u8272\u6781\u7b80\u5e03\u5c40\uff0c\u652f\u6301\u6697\u9ed1\u6a21\u5f0f",
  settingsThemeButton: "\u5207\u6362\u4e3b\u9898",
  settingsRuntimeTitle: "\u6253\u5305\u73af\u5883",
  settingsOfflineTitle: "\u79bb\u7ebf\u5206\u53d1",
  settingsOfflineNote: "\u65b0\u7248\u903b\u8f91\u4e0d\u518d\u4f9d\u8d56\u5916\u90e8 Python\uff0c\u6253\u5305\u540e\u53ef\u76f4\u63a5\u8fd0\u884c",
  settingsCaseSummaryTitle: "\u7ed3\u6848\u5907\u6ce8",
  settingsCaseSummaryNote: "\u8bb0\u4e0b\u4f60\u5df2\u786e\u8ba4\u7684 flag\uff0c\u89e3\u9898\u8def\u5f84\u548c\u63d0\u4ea4\u65f6\u9700\u8981\u7684\u8bf4\u660e\u3002",
  settingsAutoSaveTitle: "\u5de5\u4f5c\u533a\u81ea\u52a8\u4fdd\u5b58",
  settingsAutoSaveNote: "\u9898\u9762\u3001\u9644\u4ef6\u8def\u5f84\u3001\u7ec8\u5c40 flag \u548c\u8bc1\u636e\u7b14\u8bb0\u4f1a\u5728\u672c\u5730\u81ea\u52a8\u4fdd\u5b58\uff0c\u4e0b\u6b21\u6253\u5f00\u81ea\u52a8\u6062\u590d\u3002",
  settingsWorkspaceTitle: "\u5de5\u4f5c\u533a\u7ba1\u7406",
  settingsWorkspaceNote: "\u53ef\u4ee5\u5bfc\u51fa Markdown \u62a5\u544a\uff0c\u6216\u76f4\u63a5\u6e05\u7a7a\u5f53\u524d\u8c03\u67e5\u7ebf\u7d22\u3002",
  clearWorkspaceButton: "\u6e05\u7a7a\u5de5\u4f5c\u533a",
  roadmapKicker: "\u5b8c\u5584\u65b9\u5411",
  roadmapTitle: "\u4e0b\u4e00\u6b65\u5e94\u7ee7\u7eed\u505a",
  emptyArtifactPreview: "\u8fd8\u6ca1\u6709\u6dfb\u52a0\u9644\u4ef6\u3002",
  emptyArtifactDetail: "\u6ca1\u6709\u53ef\u5c55\u793a\u7684\u9644\u4ef6\uff0c\u5148\u6dfb\u52a0\u6587\u4ef6\u6216\u6587\u4ef6\u5939\u3002",
  emptyResultsCategory: "\u7b49\u5f85\u5206\u6790",
  emptyResultsSummary: "\u8fd9\u91cc\u4f1a\u7ed9\u51fa\u9898\u578b\u5224\u65ad\u3001\u4f9d\u636e\u548c\u9644\u4ef6\u5206\u6d41\u5efa\u8bae\u3002",
  emptyFlags: "\u6682\u65e0 flag \u5019\u9009\u3002",
  emptyPipeline: "\u8fd8\u6ca1\u6709\u81ea\u52a8\u751f\u6210\u7684\u884d\u751f\u6587\u4ef6\u3002",
  statusReady: "\u5148\u6dfb\u52a0\u9898\u76ee\u4fe1\u606f\u6216\u9644\u4ef6\uff0c\u518d\u8fdb\u884c\u5206\u6790\u3002",
  statusAnalyzing: "\u6b63\u5728\u5206\u6790\u9644\u4ef6\u548c\u9898\u76ee\u7ebf\u7d22...",
  statusDone: "\u5df2\u5b8c\u6210\u672c\u5730\u5206\u6d41\u4e0e\u5019\u9009\u63d0\u53d6\u3002",
  statusArtifactAdded: "\u9644\u4ef6\u5df2\u66f4\u65b0\uff0c\u53ef\u4ee5\u91cd\u65b0\u5206\u6790\u3002",
  statusFocusDescription: "\u8bf7\u76f4\u63a5\u7c98\u8d34\u9898\u9762\u3001hint \u6216\u5f53\u524d\u89c2\u5bdf\u5230\u7684\u53ef\u7591\u70b9\u3002",
  statusActionRunning: "\u6b63\u5728\u5904\u7406\u53ef\u81ea\u52a8\u6267\u884c\u7684\u7ebf\u7d22...",
  statusActionDone: "\u5df2\u751f\u6210\u65b0\u7684\u884d\u751f\u6587\u4ef6\uff0c\u5e76\u5df2\u91cd\u65b0\u5206\u6790\u3002",
  statusWorkspaceRestored: "\u5df2\u6062\u590d\u4e0a\u6b21\u5de5\u4f5c\u533a\uff0c\u5f53\u524d\u7ebf\u7d22\u5df2\u56de\u586b\u3002",
  statusWorkspaceCleared: "\u5f53\u524d\u5de5\u4f5c\u533a\u5df2\u6e05\u7a7a\u3002",
  statusReportExported: "\u5df2\u5bfc\u51fa Markdown \u62a5\u544a\uff1a",
  statusErrorPrefix: "\u5206\u6790\u5931\u8d25\uff1a",
  artifactOpen: "\u6253\u5f00\u4f4d\u7f6e",
  artifactRemove: "\u79fb\u9664",
  artifactProcess: "\u81ea\u52a8\u5904\u7406",
  flagFinalize: "\u8bbe\u4e3a\u6700\u7ec8",
  flagFinalLabel: "\u6700\u7ec8 flag",
  flagFinalEmpty: "\u8fd8\u6ca1\u6709\u6807\u8bb0\u6700\u7ec8 flag\uff0c\u53ef\u4ee5\u5148\u4ece\u5019\u9009\u5217\u8868\u91cc\u786e\u8ba4\u3002",
  flagFinalClear: "\u6e05\u7a7a\u6700\u7ec8 flag",
  evidenceStatusLabel: "\u8bc1\u636e\u72b6\u6001",
  evidenceNoteLabel: "\u5206\u6790\u7b14\u8bb0",
  evidencePinLabel: "\u6807\u4e3a\u91cd\u70b9",
  evidencePinned: "\u91cd\u70b9",
  evidenceTodo: "\u5f85\u68c0\u67e5",
  evidenceChecking: "\u68c0\u67e5\u4e2d",
  evidenceConfirmed: "\u5df2\u786e\u8ba4",
};

const VIEW_COPY = {
  workspace: {
    kicker: "\u5de5\u4f5c\u53f0",
    title: "\u4ee5\u9644\u4ef6\u4e3a\u4e2d\u5fc3\u7684 CTF \u5de5\u4f5c\u53f0",
  },
  artifacts: {
    kicker: "\u9644\u4ef6",
    title: "\u6587\u4ef6\u8d44\u4ea7\u4e0e\u5206\u7c7b\u7ed3\u679c",
  },
  results: {
    kicker: "\u7ed3\u679c",
    title: "flag \u5019\u9009\u3001\u9898\u578b\u5206\u6d41\u4e0e\u89e3\u9898\u8def\u5f84",
  },
  settings: {
    kicker: "\u8bbe\u7f6e",
    title: "\u9879\u76ee\u57fa\u7ebf\u4e0e\u6253\u5305\u7b56\u7565",
  },
};

const ROADMAP_ITEMS = [
  "\u8865\u9f50 WAV \u9891\u8c31\u56fe\u3001\u97f3\u9891 chunk \u5f02\u5e38\u68c0\u6d4b\u548c\u83ab\u65af/\u97f3\u8c03\u7c7b\u7ebf\u7d22\u63d0\u53d6\u3002",
  "\u7ed9\u6bcf\u4e2a\u9644\u4ef6\u589e\u52a0\u8bc1\u636e\u7b14\u8bb0\u4e0e\u5df2\u9a8c\u8bc1\u7ed3\u8bba\uff0c\u628a\u81ea\u52a8\u7ed3\u679c\u548c\u4eba\u5de5\u5224\u65ad\u653e\u5728\u4e00\u8d77\u3002",
  "\u5bf9 ELF\u3001PE\u3001APK \u52a0\u5165\u66f4\u7ec6\u7684\u7a0b\u5e8f\u7279\u5f81\u62bd\u53d6\uff0c\u8ba9 reverse/pwn \u5206\u6d41\u66f4\u7a33\u5b9a\u3002",
  "\u4e3a PDF / Office / \u56fe\u50cf / \u6d41\u91cf\u9898\u578b\u62c6\u51fa\u4e13\u9898\u5de5\u4f5c\u9762\u677f\uff0c\u4e0d\u518d\u53ea\u662f\u901a\u7528\u7ed3\u679c\u5361\u7247\u3002",
  "\u6dfb\u52a0\u6269\u5c55\u5f0f\u5206\u6790\u5668\u4e0e\u53d1\u5e03\u6d41\u7a0b\uff0c\u8ba9\u540e\u7eed\u89c4\u5219\u548c\u6253\u5305\u66f4\u5bb9\u6613\u8fed\u4ee3\u3002",
];

const state = {
  activeView: "workspace",
  theme: localStorage.getItem("ctf-theme") || "light",
  artifacts: [],
  analysis: null,
  casebook: {
    finalFlag: null,
    summary: "",
    evidenceByPath: {},
  },
};

const WORKSPACE_VERSION = 1;
const EVIDENCE_STATUSES = ["todo", "checking", "confirmed"];
let persistenceReady = false;
let saveTimer = null;

const elements = {
  body: document.body,
  navItems: Array.from(document.querySelectorAll(".nav-item")),
  views: {
    workspace: document.getElementById("workspace-view"),
    artifacts: document.getElementById("artifacts-view"),
    results: document.getElementById("results-view"),
    settings: document.getElementById("settings-view"),
  },
  viewKicker: document.getElementById("view-kicker"),
  viewTitle: document.getElementById("view-title"),
  appMeta: document.getElementById("app-meta"),
  settingsRuntime: document.getElementById("settings-runtime"),
  themeToggle: document.getElementById("theme-toggle"),
  settingsThemeToggle: document.getElementById("settings-theme-toggle"),
  exportReportButton: document.getElementById("export-report-button"),
  settingsExportReportButton: document.getElementById("settings-export-report-button"),
  clearWorkspaceButton: document.getElementById("clear-workspace-button"),
  statusBanner: document.getElementById("status-banner"),
  titleInput: document.getElementById("title-input"),
  tagsInput: document.getElementById("tags-input"),
  descriptionInput: document.getElementById("description-input"),
  notesInput: document.getElementById("notes-input"),
  caseSummaryInput: document.getElementById("case-summary-input"),
  pickFilesButton: document.getElementById("pick-files-button"),
  pickFolderButton: document.getElementById("pick-folder-button"),
  runAnalysisButton: document.getElementById("run-analysis-button"),
  quickFilesButton: document.getElementById("quick-files-button"),
  quickFolderButton: document.getElementById("quick-folder-button"),
  quickPasteButton: document.getElementById("quick-paste-button"),
  quickRunButton: document.getElementById("quick-run-button"),
  artifactDropzone: document.getElementById("artifact-dropzone"),
  artifactCountPill: document.getElementById("artifact-count-pill"),
  artifactPreviewList: document.getElementById("artifact-preview-list"),
  discoveryList: document.getElementById("discovery-list"),
  needsList: document.getElementById("needs-list"),
  artifactDetailList: document.getElementById("artifact-detail-list"),
  summaryCategory: document.getElementById("summary-category"),
  summaryConfidence: document.getElementById("summary-confidence"),
  summaryText: document.getElementById("summary-text"),
  summaryEvidence: document.getElementById("summary-evidence"),
  pipelineList: document.getElementById("pipeline-list"),
  flagList: document.getElementById("flag-list"),
  nextList: document.getElementById("next-list"),
  findingList: document.getElementById("finding-list"),
  toolList: document.getElementById("tool-list"),
  roadmapList: document.getElementById("roadmap-list"),
};

function applyStaticCopy() {
  document.querySelectorAll("[data-copy]").forEach((node) => {
    node.textContent = STRINGS[node.dataset.copy] || "";
  });

  elements.titleInput.placeholder = "\u4f8b\u5982\uff1aGhost Session / hidden zip / easy traffic";
  elements.tagsInput.placeholder = "web auth cookie pcap steg reverse";
  elements.descriptionInput.placeholder =
    "\u7c98\u8d34\u9898\u9762\u6216\u9898\u76ee\u7ed9\u51fa\u7684\u76f4\u63a5\u63cf\u8ff0\uff0c\u4e0d\u7528\u8fc7\u5ea6\u7cbe\u7b80\u3002";
  elements.notesInput.placeholder =
    "\u8bb0\u4e0b\u4f60\u5df2\u7ecf\u89c2\u5bdf\u5230\u7684\u73b0\u8c61\uff0c\u4f8b\u5982\uff1aPNG \u5c3e\u90e8\u50cf\u662f\u591a\u4e86 ZIP \u5934\uff0cpcap \u91cc\u6709 cookie\u3002";
  elements.caseSummaryInput.placeholder =
    "\u4f8b\u5982\uff1a\u5df2\u786e\u8ba4 flag \u6765\u81ea zip \u5c3e\u90e8\u9644\u52a0\u6570\u636e\uff0c\u5148\u63d0\u53d6\u518d\u89e3\u5305\uff0c\u6700\u7ec8\u4ece note.txt \u83b7\u5f97\u7ed3\u679c\u3002";
}

function createEmptyCasebook() {
  return {
    finalFlag: null,
    summary: "",
    evidenceByPath: {},
  };
}

function normalizeEvidenceEntry(entry) {
  const status = EVIDENCE_STATUSES.includes(entry?.status) ? entry.status : "todo";
  return {
    status,
    note: String(entry?.note || ""),
    pinned: Boolean(entry?.pinned),
  };
}

function normalizeCasebook(input) {
  const casebook = createEmptyCasebook();
  if (!input || typeof input !== "object") {
    return casebook;
  }

  if (input.finalFlag && input.finalFlag.value) {
    casebook.finalFlag = {
      value: String(input.finalFlag.value),
      source: String(input.finalFlag.source || ""),
    };
  }

  casebook.summary = String(input.summary || "");

  if (input.evidenceByPath && typeof input.evidenceByPath === "object") {
    Object.entries(input.evidenceByPath).forEach(([key, value]) => {
      casebook.evidenceByPath[key] = normalizeEvidenceEntry(value);
    });
  }

  return casebook;
}

function getEvidenceEntry(filePath) {
  if (!state.casebook.evidenceByPath[filePath]) {
    state.casebook.evidenceByPath[filePath] = normalizeEvidenceEntry(null);
  }
  return state.casebook.evidenceByPath[filePath];
}

function evidenceStatusLabel(status) {
  if (status === "checking") {
    return STRINGS.evidenceChecking;
  }
  if (status === "confirmed") {
    return STRINGS.evidenceConfirmed;
  }
  return STRINGS.evidenceTodo;
}

function compactEvidenceByPath() {
  const result = {};
  Object.entries(state.casebook.evidenceByPath || {}).forEach(([key, value]) => {
    const entry = normalizeEvidenceEntry(value);
    if (entry.note || entry.pinned || entry.status !== "todo") {
      result[key] = entry;
    }
  });
  return result;
}

function workspaceHasContent() {
  return Boolean(
    elements.titleInput.value.trim() ||
      elements.tagsInput.value.trim() ||
      elements.descriptionInput.value.trim() ||
      elements.notesInput.value.trim() ||
      elements.caseSummaryInput.value.trim() ||
      state.artifacts.length ||
      state.casebook.finalFlag,
  );
}

function workspaceHasAnalyzableInput() {
  return Boolean(
    elements.titleInput.value.trim() ||
      elements.tagsInput.value.trim() ||
      elements.descriptionInput.value.trim() ||
      elements.notesInput.value.trim() ||
      state.artifacts.length,
  );
}

function buildWorkspaceSnapshot() {
  return {
    version: WORKSPACE_VERSION,
    theme: state.theme,
    activeView: state.activeView,
    challenge: {
      title: elements.titleInput.value.trim(),
      tags: splitTags(elements.tagsInput.value),
      description: elements.descriptionInput.value.trim(),
      notes: elements.notesInput.value.trim(),
    },
    artifacts: state.artifacts.map((item) => item.path),
    casebook: {
      finalFlag: state.casebook.finalFlag,
      summary: elements.caseSummaryInput.value.trim(),
      evidenceByPath: compactEvidenceByPath(),
    },
  };
}

async function persistWorkspaceNow() {
  if (!persistenceReady) {
    return;
  }
  await window.ctfCompass.saveWorkspace(buildWorkspaceSnapshot());
}

function scheduleWorkspaceSave() {
  if (!persistenceReady) {
    return;
  }
  window.clearTimeout(saveTimer);
  saveTimer = window.setTimeout(() => {
    persistWorkspaceNow().catch(() => {
      // ignore background persistence failures
    });
  }, 260);
}

function setStatus(message, kind = "info") {
  elements.statusBanner.textContent = message;
  elements.statusBanner.classList.remove("is-hidden", "is-error");
  if (kind === "error") {
    elements.statusBanner.classList.add("is-error");
  }
}

function renderViewHeader() {
  const active = VIEW_COPY[state.activeView];
  elements.body.dataset.view = state.activeView;
  elements.viewKicker.textContent = active.kicker;
  elements.viewTitle.textContent = active.title;

  elements.navItems.forEach((button) => {
    button.classList.toggle("active", button.dataset.view === state.activeView);
  });

  Object.entries(elements.views).forEach(([view, node]) => {
    node.classList.toggle("is-active", view === state.activeView);
  });
}

function switchView(view) {
  state.activeView = view;
  elements.body.dataset.view = view;
  renderViewHeader();
  scheduleWorkspaceSave();
}

function setTheme(theme) {
  state.theme = theme;
  elements.body.dataset.theme = theme;
  localStorage.setItem("ctf-theme", theme);
  scheduleWorkspaceSave();
}

function toggleTheme() {
  setTheme(state.theme === "light" ? "dark" : "light");
}

function uniqArtifacts(items) {
  const map = new Map();
  items.forEach((item) => {
    map.set(item.path, item);
  });
  return Array.from(map.values());
}

function createArtifactPreviewRow(item) {
  const row = document.createElement("div");
  row.className = "artifact-row";
  row.dataset.family = item.family || "unknown";

  const meta = document.createElement("div");
  meta.className = "artifact-meta";

  const badge = document.createElement("span");
  badge.className = "artifact-badge";
  badge.textContent = item.badge;

  const textWrap = document.createElement("div");
  textWrap.className = "artifact-text";

  const title = document.createElement("strong");
  title.textContent = item.name;

  const subtitle = document.createElement("p");
  subtitle.textContent = `${item.familyLabel}  |  ${item.sizeLabel}`;

  textWrap.append(title, subtitle);
  meta.append(badge, textWrap);

  const removeButton = document.createElement("button");
  removeButton.className = "icon-button";
  removeButton.type = "button";
  removeButton.textContent = "\u2212";
  removeButton.title = STRINGS.artifactRemove;
  removeButton.addEventListener("click", () => {
    state.artifacts = state.artifacts.filter((artifact) => artifact.path !== item.path);
    renderAll();
    scheduleWorkspaceSave();
  });

  row.append(meta, removeButton);
  return row;
}

function renderArtifactPreview() {
  elements.artifactCountPill.textContent = String(state.artifacts.length);
  elements.artifactPreviewList.innerHTML = "";

  if (!state.artifacts.length) {
    const empty = document.createElement("p");
    empty.className = "empty-copy";
    empty.textContent = STRINGS.emptyArtifactPreview;
    elements.artifactPreviewList.append(empty);
    return;
  }

  sortArtifactsForDisplay(state.artifacts).forEach((item) => {
    elements.artifactPreviewList.append(createArtifactPreviewRow(item));
  });
}

function inferPreviewFindings() {
  if (!state.artifacts.length) {
    return [STRINGS.statusReady];
  }

  const familyCount = state.artifacts.reduce((accumulator, item) => {
    accumulator[item.family] = (accumulator[item.family] || 0) + 1;
    return accumulator;
  }, {});

  const findings = [`\u5df2\u52a0\u8f7d ${state.artifacts.length} \u4e2a\u9644\u4ef6\uff0c\u5206\u6790\u65f6\u4f1a\u4f18\u5148\u4ece\u9644\u4ef6\u8bc6\u522b\u9898\u578b\u3002`];

  if (familyCount.image) {
    findings.push("\u56fe\u50cf\u7c7b\u9644\u4ef6\u5df2\u68c0\u6d4b\u5230\uff0c\u53ef\u80fd\u6d89\u53ca\u9690\u5199\u3001\u5143\u6570\u636e\u6216\u5c3e\u90e8\u9690\u85cf\u3002");
  }
  if (familyCount.network) {
    findings.push("\u6d41\u91cf\u7c7b\u9644\u4ef6\u5df2\u68c0\u6d4b\u5230\uff0c\u53ef\u4ee5\u8fdb\u5165 HTTP / DNS / \u4f1a\u8bdd\u91cd\u7ec4\u5206\u6790\u3002");
  }
  if (familyCount.binary) {
    findings.push("\u4e8c\u8fdb\u5236\u9644\u4ef6\u5df2\u68c0\u6d4b\u5230\uff0c\u7ed3\u679c\u4f1a\u504f\u5411 reverse / pwn \u5206\u6d41\u3002");
  }
  if (familyCount.text) {
    findings.push("\u6587\u672c\u7c7b\u9644\u4ef6\u4f1a\u81ea\u52a8\u626b flag \u6837\u5f0f\u3001base64 \u548c hex \u7ebf\u7d22\u3002");
  }

  return findings;
}

function renderDiscoveryPanel() {
  elements.discoveryList.innerHTML = "";
  const items = state.analysis
    ? state.analysis.quickFindings.concat(state.analysis.warnings || [])
    : inferPreviewFindings();

  items.forEach((item) => {
    const box = document.createElement("div");
    box.className = "stack-item";
    box.textContent = item;
    elements.discoveryList.append(box);
  });
}

function renderNeedsPanel(items) {
  elements.needsList.innerHTML = "";
  items.forEach((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    elements.needsList.append(li);
  });
}

function renderRoadmap() {
  elements.roadmapList.innerHTML = "";
  ROADMAP_ITEMS.forEach((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    elements.roadmapList.append(li);
  });
}

function sortArtifactsForDisplay(items) {
  return [...items].sort((left, right) => {
    const leftPinned = getEvidenceEntry(left.path).pinned ? 1 : 0;
    const rightPinned = getEvidenceEntry(right.path).pinned ? 1 : 0;
    if (leftPinned !== rightPinned) {
      return rightPinned - leftPinned;
    }
    return left.name.localeCompare(right.name, "zh-CN");
  });
}

function setFinalFlag(candidate) {
  state.casebook.finalFlag = candidate ? { value: candidate.value, source: candidate.source } : null;
  renderResults();
  scheduleWorkspaceSave();
}

function clearFinalFlag() {
  state.casebook.finalFlag = null;
  renderResults();
  scheduleWorkspaceSave();
}

function createFlagCard(candidate, isFinal) {
  const row = document.createElement("div");
  row.className = `stack-item flag-item${isFinal ? " is-final" : ""}`;

  const head = document.createElement("div");
  head.className = "flag-item-head";
  head.innerHTML = `<div><strong>${escapeHtml(candidate.value)}</strong><small>${escapeHtml(candidate.source || "")}</small></div>`;

  const actions = document.createElement("div");
  actions.className = "flag-actions";

  const actionButton = document.createElement("button");
  actionButton.className = "text-link";
  actionButton.type = "button";
  actionButton.textContent = isFinal ? STRINGS.flagFinalLabel : STRINGS.flagFinalize;
  actionButton.addEventListener("click", () => {
    if (isFinal) {
      clearFinalFlag();
      return;
    }
    setFinalFlag(candidate);
  });

  actions.append(actionButton);
  head.append(actions);
  row.append(head);
  return row;
}

function createEvidenceSummary(filePath) {
  const evidence = getEvidenceEntry(filePath);
  if (!evidence.note && !evidence.pinned && evidence.status === "todo") {
    return null;
  }

  const wrap = document.createElement("div");
  wrap.className = "evidence-summary";

  const chipRow = document.createElement("div");
  chipRow.className = "chip-row evidence-chip-row";

  const statusChip = document.createElement("span");
  statusChip.className = "chip";
  statusChip.textContent = evidenceStatusLabel(evidence.status);
  chipRow.append(statusChip);

  if (evidence.pinned) {
    const pinnedChip = document.createElement("span");
    pinnedChip.className = "chip tool-chip";
    pinnedChip.textContent = STRINGS.evidencePinned;
    chipRow.append(pinnedChip);
  }

  wrap.append(chipRow);

  if (evidence.note) {
    const note = document.createElement("p");
    note.className = "detail-summary";
    note.textContent = evidence.note;
    wrap.append(note);
  }

  return wrap;
}

function createEvidenceEditor(filePath) {
  const evidence = getEvidenceEntry(filePath);
  const editor = document.createElement("div");
  editor.className = "evidence-editor";

  const toolbar = document.createElement("div");
  toolbar.className = "evidence-toolbar";

  const selectLabel = document.createElement("label");
  selectLabel.className = "field evidence-field";

  const selectTitle = document.createElement("span");
  selectTitle.textContent = STRINGS.evidenceStatusLabel;

  const select = document.createElement("select");
  select.className = "evidence-select";
  EVIDENCE_STATUSES.forEach((status) => {
    const option = document.createElement("option");
    option.value = status;
    option.textContent = evidenceStatusLabel(status);
    option.selected = evidence.status === status;
    select.append(option);
  });
  select.addEventListener("change", () => {
    evidence.status = select.value;
    scheduleWorkspaceSave();
  });
  selectLabel.append(selectTitle, select);

  const pinButton = document.createElement("button");
  pinButton.className = `text-link toggle-chip${evidence.pinned ? " active" : ""}`;
  pinButton.type = "button";
  pinButton.textContent = STRINGS.evidencePinLabel;
  pinButton.addEventListener("click", () => {
    evidence.pinned = !evidence.pinned;
    pinButton.classList.toggle("active", evidence.pinned);
    renderAll();
    scheduleWorkspaceSave();
  });

  toolbar.append(selectLabel, pinButton);
  editor.append(toolbar);

  const noteField = document.createElement("label");
  noteField.className = "field field-full evidence-field";

  const noteLabel = document.createElement("span");
  noteLabel.textContent = STRINGS.evidenceNoteLabel;

  const noteInput = document.createElement("textarea");
  noteInput.className = "evidence-note";
  noteInput.rows = 4;
  noteInput.value = evidence.note;
  noteInput.addEventListener("input", () => {
    evidence.note = noteInput.value;
    scheduleWorkspaceSave();
  });

  noteField.append(noteLabel, noteInput);
  editor.append(noteField);
  return editor;
}

function renderResults() {
  if (!state.analysis) {
    elements.summaryCategory.textContent = STRINGS.emptyResultsCategory;
    elements.summaryConfidence.textContent = "--";
    elements.summaryText.textContent = STRINGS.emptyResultsSummary;
    elements.summaryEvidence.innerHTML = "";
    elements.pipelineList.innerHTML = `<p class="empty-copy">${STRINGS.emptyPipeline}</p>`;
    elements.flagList.innerHTML = `<p class="empty-copy">${STRINGS.emptyFlags}</p>`;
    elements.nextList.innerHTML = "";
    elements.findingList.innerHTML = `<p class="empty-copy">${STRINGS.emptyArtifactDetail}</p>`;
    elements.toolList.innerHTML = "";
    renderNeedsPanel(ROADMAP_ITEMS);
    return;
  }

  const result = state.analysis;
  state.casebook.summary = elements.caseSummaryInput.value.trim();
  elements.summaryCategory.textContent = result.classification.label;
  elements.summaryConfidence.textContent = result.classification.confidence.toFixed(2);
  elements.summaryText.textContent = result.classification.reason;
  elements.summaryEvidence.innerHTML = "";
  result.classification.evidence.forEach((item) => {
    const chip = document.createElement("span");
    chip.className = "chip";
    chip.textContent = item;
    elements.summaryEvidence.append(chip);
  });

  elements.pipelineList.innerHTML = "";
  if (!result.pipelineLog || !result.pipelineLog.length) {
    const emptyPipeline = document.createElement("p");
    emptyPipeline.className = "empty-copy";
    emptyPipeline.textContent = STRINGS.emptyPipeline;
    elements.pipelineList.append(emptyPipeline);
  } else {
    result.pipelineLog.forEach((entry) => {
      const row = document.createElement("div");
      row.className = "stack-item";
      const createdNames = (entry.createdArtifacts || []).map((artifact) => artifact.name).join("  |  ");
      row.innerHTML = `<strong>${escapeHtml(entry.sourceName)} \u2192 ${escapeHtml(entry.actionLabel)}</strong><p>${escapeHtml(
        entry.message,
      )}</p><small>${escapeHtml(createdNames)}</small>`;
      elements.pipelineList.append(row);
    });
  }

  elements.flagList.innerHTML = "";
  if (state.casebook.finalFlag) {
    elements.flagList.append(createFlagCard(state.casebook.finalFlag, true));
  } else {
    const emptyFinal = document.createElement("div");
    emptyFinal.className = "stack-item final-flag-empty";
    emptyFinal.innerHTML = `<strong>${STRINGS.flagFinalLabel}</strong><small>${STRINGS.flagFinalEmpty}</small>`;
    elements.flagList.append(emptyFinal);
  }

  if (!result.flagCandidates.length) {
    const empty = document.createElement("p");
    empty.className = "empty-copy";
    empty.textContent = result.emptyFlagMessage;
    elements.flagList.append(empty);
  } else {
    result.flagCandidates.forEach((item) => {
      const isFinal =
        state.casebook.finalFlag &&
        state.casebook.finalFlag.value === item.value &&
        state.casebook.finalFlag.source === item.source;
      elements.flagList.append(createFlagCard(item, isFinal));
    });
  }

  elements.nextList.innerHTML = "";
  result.classification.nextMoves.forEach((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    elements.nextList.append(li);
  });

  elements.findingList.innerHTML = "";
  sortArtifactsForDisplay(result.artifacts).forEach((artifact) => {
    elements.findingList.append(createDetailCard(artifact, { editableEvidence: false }));
  });

  elements.toolList.innerHTML = "";
  result.classification.tools.forEach((tool) => {
    const chip = document.createElement("span");
    chip.className = "chip tool-chip";
    chip.textContent = tool;
    elements.toolList.append(chip);
  });

  renderNeedsPanel(result.inferredNeeds);
}

function createDetailCard(artifact, options = {}) {
  const card = document.createElement("article");
  card.className = "detail-card";
  card.dataset.family = artifact.family || "unknown";

  const parts = [`${artifact.familyLabel}  |  ${artifact.sizeLabel}  |  ${artifact.badge}`];
  if (artifact.sourceKind === "generated" && artifact.generatedBy) {
    parts.push(`\u81ea\u52a8\u751f\u6210\uff1a${artifact.generatedBy}`);
  }

  const head = document.createElement("div");
  head.className = "detail-head";
  head.innerHTML = `<div><strong>${escapeHtml(artifact.name)}</strong><p>${escapeHtml(
    parts.join("  |  "),
  )}</p></div>`;

  const actions = document.createElement("div");
  actions.className = "detail-actions";

  const openButton = document.createElement("button");
  openButton.className = "text-link";
  openButton.type = "button";
  openButton.textContent = STRINGS.artifactOpen;
  openButton.addEventListener("click", () => {
    window.ctfCompass.revealArtifact(artifact.path);
  });
  actions.append(openButton);

  if (artifact.actions && artifact.actions.length) {
    artifact.actions.forEach((action) => {
      const actionButton = document.createElement("button");
      actionButton.className = "text-link";
      actionButton.type = "button";
      actionButton.textContent = action.label;
      actionButton.title = STRINGS.artifactProcess;
      actionButton.addEventListener("click", () => {
        runArtifactAction(action.id, artifact.path);
      });
      actions.append(actionButton);
    });
  }

  head.append(actions);
  card.append(head);

  if (artifact.summary) {
    const summary = document.createElement("p");
    summary.className = "detail-summary";
    summary.textContent = artifact.summary;
    card.append(summary);
  }

  const entries = artifact.highlights && artifact.highlights.length ? artifact.highlights : artifact.suggestions || [];
  if (entries.length) {
    const lines = document.createElement("div");
    lines.className = "detail-bullets";
    entries.forEach((item) => {
      const line = document.createElement("div");
      line.className = "detail-line";
      line.textContent = item;
      lines.append(line);
    });
    card.append(lines);
  }

  if (options.editableEvidence) {
    card.append(createEvidenceEditor(artifact.path));
  } else {
    const summary = createEvidenceSummary(artifact.path);
    if (summary) {
      card.append(summary);
    }
  }

  return card;
}

async function runArtifactAction(actionId, filePath) {
  try {
    setStatus(STRINGS.statusActionRunning);
    const result = await window.ctfCompass.runArtifactAction({ actionId, filePath });
    if (result.generatedArtifacts && result.generatedArtifacts.length) {
      state.artifacts = uniqArtifacts(state.artifacts.concat(result.generatedArtifacts));
    }
    await runAnalysis();
    setStatus(result.message || STRINGS.statusActionDone);
  } catch (error) {
    setStatus(`${STRINGS.statusErrorPrefix} ${error.message}`, "error");
  }
}

function renderArtifactDetails() {
  elements.artifactDetailList.innerHTML = "";
  const source = state.analysis ? state.analysis.artifacts : state.artifacts;

  if (!source.length) {
    const empty = document.createElement("p");
    empty.className = "empty-copy";
    empty.textContent = STRINGS.emptyArtifactDetail;
    elements.artifactDetailList.append(empty);
    return;
  }

  sortArtifactsForDisplay(source).forEach((artifact) => {
    elements.artifactDetailList.append(createDetailCard(artifact, { editableEvidence: true }));
  });
}

function renderAll() {
  renderViewHeader();
  renderArtifactPreview();
  renderDiscoveryPanel();
  renderResults();
  renderArtifactDetails();
  renderRoadmap();
}

function splitTags(value) {
  return value
    .split(/\s+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

async function runAnalysis(options = {}) {
  const { focusResults = true, doneMessage = STRINGS.statusDone } = options;
  try {
    setStatus(STRINGS.statusAnalyzing);
    const result = await window.ctfCompass.analyzeChallenge({
      title: elements.titleInput.value.trim(),
      description: elements.descriptionInput.value.trim(),
      notes: elements.notesInput.value.trim(),
      tags: splitTags(elements.tagsInput.value),
      artifacts: state.artifacts.map((item) => item.path),
    });
    state.analysis = result;
    renderAll();
    if (focusResults) {
      switchView("results");
    } else {
      renderViewHeader();
    }
    scheduleWorkspaceSave();
    setStatus(doneMessage);
  } catch (error) {
    setStatus(`${STRINGS.statusErrorPrefix} ${error.message}`, "error");
  }
}

async function appendPreparedArtifacts(promise) {
  try {
    const items = await promise;
    if (items.length) {
      state.artifacts = uniqArtifacts(state.artifacts.concat(items));
      renderAll();
      scheduleWorkspaceSave();
      setStatus(STRINGS.statusArtifactAdded);
    }
  } catch (error) {
    setStatus(`${STRINGS.statusErrorPrefix} ${error.message}`, "error");
  }
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function buildReportMarkdown() {
  if (!state.analysis) {
    return null;
  }

  const snapshot = buildWorkspaceSnapshot();
  const lines = [
    `# ${snapshot.challenge.title || "CTF Compass Report"}`,
    "",
    `- Generated: ${new Date().toLocaleString("zh-CN")}`,
    `- Category: ${state.analysis.classification.label}`,
    `- Confidence: ${state.analysis.classification.confidence.toFixed(2)}`,
    `- Artifacts: ${state.analysis.artifacts.length}`,
    "",
  ];

  if (state.casebook.finalFlag?.value) {
    lines.push("## Final Flag", "", `- ${state.casebook.finalFlag.value}`, "");
  }

  if (snapshot.challenge.tags.length) {
    lines.push("## Tags", "", snapshot.challenge.tags.map((item) => `- ${item}`).join("\n"), "");
  }

  if (snapshot.challenge.description) {
    lines.push("## Challenge Description", "", snapshot.challenge.description, "");
  }

  if (snapshot.challenge.notes) {
    lines.push("## Working Notes", "", snapshot.challenge.notes, "");
  }

  if (snapshot.casebook.summary) {
    lines.push("## Analyst Conclusion", "", snapshot.casebook.summary, "");
  }

  lines.push("## Classification", "", state.analysis.classification.reason, "");

  if (state.analysis.classification.evidence?.length) {
    lines.push("### Evidence", "");
    state.analysis.classification.evidence.forEach((item) => lines.push(`- ${item}`));
    lines.push("");
  }

  if (state.analysis.flagCandidates?.length) {
    lines.push("## Flag Candidates", "");
    state.analysis.flagCandidates.forEach((item) => lines.push(`- ${item.value} (${item.source})`));
    lines.push("");
  }

  if (state.analysis.pipelineLog?.length) {
    lines.push("## Pipeline", "");
    state.analysis.pipelineLog.forEach((item) => {
      lines.push(`- ${item.sourceName} -> ${item.actionLabel}: ${item.message}`);
    });
    lines.push("");
  }

  if (state.analysis.classification.nextMoves?.length) {
    lines.push("## Next Steps", "");
    state.analysis.classification.nextMoves.forEach((item) => lines.push(`- ${item}`));
    lines.push("");
  }

  if (state.analysis.classification.tools?.length) {
    lines.push("## Tools", "");
    state.analysis.classification.tools.forEach((item) => lines.push(`- ${item}`));
    lines.push("");
  }

  const evidenceEntries = Object.entries(compactEvidenceByPath());
  if (evidenceEntries.length) {
    lines.push("## Evidence Notebook", "");
    evidenceEntries.forEach(([filePath, entry]) => {
      const artifact = (state.analysis?.artifacts || state.artifacts).find((item) => item.path === filePath);
      lines.push(`### ${artifact?.name || filePath}`);
      lines.push(`- Status: ${evidenceStatusLabel(entry.status)}`);
      lines.push(`- Pinned: ${entry.pinned ? "yes" : "no"}`);
      if (entry.note) {
        lines.push("", entry.note);
      }
      lines.push("");
    });
  }

  return `${lines.join("\n")}\n`;
}

async function exportReport() {
  try {
    if (!state.analysis) {
      throw new Error("\u8bf7\u5148\u8fd0\u884c\u4e00\u6b21\u5206\u6790\u518d\u5bfc\u51fa\u62a5\u544a\u3002");
    }
    const title = elements.titleInput.value.trim() || "ctf-compass-report";
    const result = await window.ctfCompass.exportReport({
      suggestedName: `${title.replace(/[\\\\/:*?\"<>|]+/g, "-")}.md`,
      content: buildReportMarkdown(),
    });
    if (result?.filePath) {
      setStatus(`${STRINGS.statusReportExported} ${result.filePath}`);
    }
  } catch (error) {
    setStatus(`${STRINGS.statusErrorPrefix} ${error.message}`, "error");
  }
}

async function clearWorkspace() {
  try {
    persistenceReady = false;
    state.artifacts = [];
    state.analysis = null;
    state.casebook = createEmptyCasebook();
    elements.titleInput.value = "";
    elements.tagsInput.value = "";
    elements.descriptionInput.value = "";
    elements.notesInput.value = "";
    elements.caseSummaryInput.value = "";
    await window.ctfCompass.clearWorkspace();
    renderAll();
    switchView("workspace");
    persistenceReady = true;
    setStatus(STRINGS.statusWorkspaceCleared);
  } catch (error) {
    persistenceReady = true;
    setStatus(`${STRINGS.statusErrorPrefix} ${error.message}`, "error");
  }
}

async function hydrateWorkspace() {
  try {
    const snapshot = await window.ctfCompass.loadWorkspace();
    if (!snapshot) {
      persistenceReady = true;
      return;
    }

    persistenceReady = false;
    state.casebook = normalizeCasebook(snapshot.casebook);
    state.activeView = VIEW_COPY[snapshot.activeView] ? snapshot.activeView : "workspace";

    if (snapshot.theme) {
      setTheme(snapshot.theme);
    }

    elements.titleInput.value = String(snapshot.challenge?.title || "");
    elements.tagsInput.value = Array.isArray(snapshot.challenge?.tags) ? snapshot.challenge.tags.join(" ") : "";
    elements.descriptionInput.value = String(snapshot.challenge?.description || "");
    elements.notesInput.value = String(snapshot.challenge?.notes || "");
    elements.caseSummaryInput.value = state.casebook.summary;

    if (Array.isArray(snapshot.artifacts) && snapshot.artifacts.length) {
      state.artifacts = uniqArtifacts(await window.ctfCompass.prepareArtifacts(snapshot.artifacts));
    }

    renderAll();
    switchView(state.activeView);
    persistenceReady = true;

    if (workspaceHasAnalyzableInput()) {
      await runAnalysis({ focusResults: false, doneMessage: STRINGS.statusWorkspaceRestored });
      switchView(state.activeView);
    } else if (workspaceHasContent()) {
      setStatus(STRINGS.statusWorkspaceRestored);
    }
  } catch (error) {
    persistenceReady = true;
    setStatus(`${STRINGS.statusErrorPrefix} ${error.message}`, "error");
  }
}

async function hydrateMeta() {
  const meta = await window.ctfCompass.getMeta();
  const text = `${meta.mode}  |  v${meta.version}`;
  elements.appMeta.textContent = text;
  elements.settingsRuntime.textContent = text;
}

elements.navItems.forEach((button) => {
  button.addEventListener("click", () => {
    switchView(button.dataset.view);
  });
});

elements.themeToggle.addEventListener("click", toggleTheme);
elements.settingsThemeToggle.addEventListener("click", toggleTheme);
elements.exportReportButton.addEventListener("click", exportReport);
elements.settingsExportReportButton.addEventListener("click", exportReport);
elements.clearWorkspaceButton.addEventListener("click", clearWorkspace);
elements.pickFilesButton.addEventListener("click", () => appendPreparedArtifacts(window.ctfCompass.pickFiles()));
elements.pickFolderButton.addEventListener("click", () => appendPreparedArtifacts(window.ctfCompass.pickFolder()));
elements.quickFilesButton.addEventListener("click", () => appendPreparedArtifacts(window.ctfCompass.pickFiles()));
elements.quickFolderButton.addEventListener("click", () => appendPreparedArtifacts(window.ctfCompass.pickFolder()));
elements.quickPasteButton.addEventListener("click", () => {
  elements.descriptionInput.focus();
  setStatus(STRINGS.statusFocusDescription);
});
elements.runAnalysisButton.addEventListener("click", runAnalysis);
elements.quickRunButton.addEventListener("click", runAnalysis);
elements.artifactDropzone.addEventListener("click", () => appendPreparedArtifacts(window.ctfCompass.pickFiles()));

[elements.titleInput, elements.tagsInput, elements.descriptionInput, elements.notesInput, elements.caseSummaryInput].forEach((input) => {
  input.addEventListener("input", () => {
    state.casebook.summary = elements.caseSummaryInput.value.trim();
    scheduleWorkspaceSave();
  });
});

elements.artifactDropzone.addEventListener("dragover", (event) => {
  event.preventDefault();
  elements.artifactDropzone.classList.add("is-dragover");
});

elements.artifactDropzone.addEventListener("dragleave", () => {
  elements.artifactDropzone.classList.remove("is-dragover");
});

elements.artifactDropzone.addEventListener("drop", (event) => {
  event.preventDefault();
  elements.artifactDropzone.classList.remove("is-dragover");
  const paths = Array.from(event.dataTransfer.files || [])
    .map((file) => file.path)
    .filter(Boolean);
  if (paths.length) {
    appendPreparedArtifacts(window.ctfCompass.prepareArtifacts(paths));
  }
});

setTheme(state.theme);
applyStaticCopy();
renderAll();
setStatus(STRINGS.statusReady);
hydrateMeta().catch((error) => {
  setStatus(`${STRINGS.statusErrorPrefix} ${error.message}`, "error");
});
hydrateWorkspace();
