const STORAGE_KEY = "link-launcher.tasks.v1";

const PLATFORM_LABELS = {
  general: "通用",
  "12306": "12306",
  taobao: "淘宝",
  tmall: "天猫",
  jd: "京东",
  pdd: "拼多多",
};

const MODE_LABELS = {
  normal: "普通链接",
  unpaid: "待付款链接",
  reservation: "预约/候补入口",
};

const ALLOWED_PROTOCOLS = new Set([
  "http:",
  "https:",
  "taobao:",
  "tbopen:",
  "tmall:",
  "openapp.jdmobile:",
  "jingdong:",
  "pinduoduo:",
  "pddopen:",
  "railway12306:",
  "cn.12306:",
]);

const bridge = window.linkLauncher || {
  openExternal: async ({ url }) => {
    window.open(url, "_blank", "noopener,noreferrer");
    return { opened: true, url };
  },
  notify: async () => ({ shown: false }),
  getMeta: async () => ({ mode: "browser", version: "local" }),
};

const state = {
  tasks: loadTasks(),
  activeFilter: "all",
};

const elements = {
  form: document.getElementById("task-form"),
  name: document.getElementById("task-name"),
  platform: document.getElementById("task-platform"),
  mode: document.getElementById("task-mode"),
  lead: document.getElementById("task-lead"),
  url: document.getElementById("task-url"),
  time: document.getElementById("task-time"),
  sound: document.getElementById("task-sound"),
  status: document.getElementById("status"),
  taskList: document.getElementById("task-list"),
  openNow: document.getElementById("open-now-button"),
  resetForm: document.getElementById("reset-form-button"),
  clearDone: document.getElementById("clear-done-button"),
  filterButtons: Array.from(document.querySelectorAll("[data-filter]")),
};

function loadTasks() {
  try {
    const parsed = JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
    return Array.isArray(parsed) ? parsed.map(normalizeTask).filter(Boolean) : [];
  } catch (_error) {
    return [];
  }
}

function normalizeTask(task) {
  if (!task || typeof task !== "object") {
    return null;
  }

  return {
    id: String(task.id || crypto.randomUUID()),
    name: String(task.name || ""),
    platform: PLATFORM_LABELS[task.platform] ? task.platform : "general",
    mode: MODE_LABELS[task.mode] ? task.mode : "normal",
    url: String(task.url || ""),
    scheduledAt: task.scheduledAt ? String(task.scheduledAt) : "",
    leadSeconds: clampNumber(task.leadSeconds, 0, 600, 0),
    sound: task.sound !== false,
    firedFor: String(task.firedFor || ""),
    firedAt: task.firedAt ? String(task.firedAt) : "",
    lastOpenedAt: task.lastOpenedAt ? String(task.lastOpenedAt) : "",
  };
}

function saveTasks() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state.tasks, null, 2));
}

function clampNumber(value, min, max, fallback) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, numeric));
}

function normalizeExternalUrl(value) {
  const trimmed = String(value || "").trim();
  if (!trimmed) {
    throw new Error("链接不能为空。");
  }

  const hasProtocol = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed);
  const target = hasProtocol ? trimmed : `https://${trimmed}`;
  const parsed = new URL(target);
  const protocol = parsed.protocol.toLowerCase();

  if (!ALLOWED_PROTOCOLS.has(protocol)) {
    throw new Error("链接协议不在允许范围内。");
  }

  return target;
}

function readFormTask() {
  const url = normalizeExternalUrl(elements.url.value);
  const name = elements.name.value.trim() || `${PLATFORM_LABELS[elements.platform.value]} ${MODE_LABELS[elements.mode.value]}`;
  const scheduledAt = elements.time.value ? new Date(elements.time.value).toISOString() : "";

  return {
    id: crypto.randomUUID(),
    name,
    platform: elements.platform.value,
    mode: elements.mode.value,
    url,
    scheduledAt,
    leadSeconds: clampNumber(elements.lead.value, 0, 600, 0),
    sound: elements.sound.checked,
    firedFor: "",
    firedAt: "",
    lastOpenedAt: "",
  };
}

function resetForm() {
  elements.form.reset();
  elements.lead.value = "0";
  elements.sound.checked = true;
  elements.name.focus();
}

function triggerKey(task) {
  return `${task.scheduledAt}|${task.leadSeconds}`;
}

function triggerTime(task) {
  if (!task.scheduledAt) {
    return null;
  }
  return new Date(task.scheduledAt).getTime() - task.leadSeconds * 1000;
}

function taskStatus(task) {
  const at = triggerTime(task);
  if (!at) {
    return { label: "手动", tone: "neutral" };
  }

  if (task.firedFor === triggerKey(task)) {
    return { label: "已触发", tone: "done" };
  }

  const delta = at - Date.now();
  if (delta <= 0) {
    return { label: "待触发", tone: "soon" };
  }

  return { label: formatDuration(delta), tone: delta < 60_000 ? "soon" : "neutral" };
}

function formatDuration(ms) {
  const total = Math.max(0, Math.ceil(ms / 1000));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;

  if (hours) {
    return `${hours}小时${String(minutes).padStart(2, "0")}分`;
  }
  if (minutes) {
    return `${minutes}分${String(seconds).padStart(2, "0")}秒`;
  }
  return `${seconds}秒`;
}

function formatDateTime(value) {
  if (!value) {
    return "未设置时间";
  }
  return new Date(value).toLocaleString("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function setStatus(message, tone = "neutral") {
  elements.status.textContent = message;
  elements.status.dataset.tone = tone;
}

function playTone() {
  const Context = window.AudioContext || window.webkitAudioContext;
  if (!Context) {
    return;
  }

  const audio = new Context();
  const oscillator = audio.createOscillator();
  const gain = audio.createGain();
  oscillator.type = "sine";
  oscillator.frequency.value = 720;
  gain.gain.setValueAtTime(0.001, audio.currentTime);
  gain.gain.exponentialRampToValueAtTime(0.16, audio.currentTime + 0.02);
  gain.gain.exponentialRampToValueAtTime(0.001, audio.currentTime + 0.45);
  oscillator.connect(gain).connect(audio.destination);
  oscillator.start();
  oscillator.stop(audio.currentTime + 0.5);
}

async function openTask(task, source = "manual") {
  const result = await bridge.openExternal({ url: task.url, label: task.name });
  task.lastOpenedAt = new Date().toISOString();

  if (source === "schedule") {
    task.firedFor = triggerKey(task);
    task.firedAt = task.lastOpenedAt;
    if (task.sound) {
      playTone();
    }
    bridge.notify({
      title: "Link Launcher",
      body: `已打开：${task.name}`,
    }).catch(() => {});
  }

  saveTasks();
  renderTasks();
  setStatus(`已打开：${result.url}`, "ok");
}

function duplicateTask(task) {
  const copy = {
    ...task,
    id: crypto.randomUUID(),
    name: `${task.name} 副本`,
    firedFor: "",
    firedAt: "",
    lastOpenedAt: "",
  };
  state.tasks.unshift(copy);
  saveTasks();
  renderTasks();
  setStatus("已复制任务", "ok");
}

function removeTask(taskId) {
  state.tasks = state.tasks.filter((task) => task.id !== taskId);
  saveTasks();
  renderTasks();
  setStatus("已删除任务", "ok");
}

function visibleTasks() {
  const filtered =
    state.activeFilter === "all"
      ? state.tasks
      : state.tasks.filter((task) => {
          if (state.activeFilter === "taobao") {
            return task.platform === "taobao" || task.platform === "tmall";
          }
          return task.platform === state.activeFilter;
        });

  return filtered.slice().sort((a, b) => {
    const aTime = triggerTime(a) || Number.MAX_SAFE_INTEGER;
    const bTime = triggerTime(b) || Number.MAX_SAFE_INTEGER;
    return aTime - bTime;
  });
}

function createTaskCard(task) {
  const status = taskStatus(task);
  const card = document.createElement("article");
  card.className = "task-card";
  card.dataset.platform = task.platform;

  const meta = document.createElement("div");
  meta.className = "task-meta";

  const badge = document.createElement("span");
  badge.className = "platform-badge";
  badge.textContent = PLATFORM_LABELS[task.platform];

  const copy = document.createElement("div");
  copy.className = "task-copy";

  const title = document.createElement("strong");
  title.textContent = task.name;

  const details = document.createElement("p");
  details.textContent = `${MODE_LABELS[task.mode]} · ${formatDateTime(task.scheduledAt)} · 提前 ${task.leadSeconds} 秒`;

  const url = document.createElement("small");
  url.textContent = task.url;

  copy.append(title, details, url);
  meta.append(badge, copy);

  const actions = document.createElement("div");
  actions.className = "task-actions";

  const countdown = document.createElement("span");
  countdown.className = "countdown";
  countdown.dataset.tone = status.tone;
  countdown.textContent = status.label;

  const openButton = document.createElement("button");
  openButton.className = "icon-button";
  openButton.type = "button";
  openButton.title = "打开";
  openButton.innerHTML =
    '<svg viewBox="0 0 24 24" fill="none"><path d="M7 17 17 7M9 7h8v8"/><path d="M5 5h6M5 5v6M19 19h-6M19 19v-6"/></svg>';
  openButton.addEventListener("click", () => {
    openTask(task).catch((error) => setStatus(error.message, "error"));
  });

  const duplicateButton = document.createElement("button");
  duplicateButton.className = "icon-button";
  duplicateButton.type = "button";
  duplicateButton.title = "复制任务";
  duplicateButton.innerHTML =
    '<svg viewBox="0 0 24 24" fill="none"><path d="M8 8h10v10H8z"/><path d="M6 16H5a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1"/></svg>';
  duplicateButton.addEventListener("click", () => duplicateTask(task));

  const deleteButton = document.createElement("button");
  deleteButton.className = "icon-button danger";
  deleteButton.type = "button";
  deleteButton.title = "删除";
  deleteButton.innerHTML =
    '<svg viewBox="0 0 24 24" fill="none"><path d="M6 7h12M10 11v6M14 11v6M9 7l1-2h4l1 2M8 7l1 12h6l1-12"/></svg>';
  deleteButton.addEventListener("click", () => removeTask(task.id));

  actions.append(countdown, openButton, duplicateButton, deleteButton);
  card.append(meta, actions);
  return card;
}

function renderTasks() {
  elements.taskList.innerHTML = "";
  const tasks = visibleTasks();

  if (!tasks.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "当前筛选下没有任务。";
    elements.taskList.append(empty);
    return;
  }

  tasks.forEach((task) => {
    elements.taskList.append(createTaskCard(task));
  });
}

function tickSchedules() {
  let changed = false;
  state.tasks.forEach((task) => {
    const at = triggerTime(task);
    if (!at || task.firedFor === triggerKey(task)) {
      return;
    }

    if (Date.now() >= at) {
      changed = true;
      openTask(task, "schedule").catch((error) => setStatus(error.message, "error"));
    }
  });

  if (!changed) {
    renderTasks();
  }
}

elements.form.addEventListener("submit", (event) => {
  event.preventDefault();
  try {
    const task = readFormTask();
    state.tasks.unshift(task);
    saveTasks();
    renderTasks();
    resetForm();
    setStatus("已添加任务", "ok");
  } catch (error) {
    setStatus(error.message, "error");
  }
});

elements.openNow.addEventListener("click", () => {
  try {
    const task = readFormTask();
    openTask(task).catch((error) => setStatus(error.message, "error"));
  } catch (error) {
    setStatus(error.message, "error");
  }
});

elements.resetForm.addEventListener("click", resetForm);

elements.clearDone.addEventListener("click", () => {
  state.tasks = state.tasks.filter((task) => task.firedFor !== triggerKey(task));
  saveTasks();
  renderTasks();
  setStatus("已清理已触发任务", "ok");
});

elements.filterButtons.forEach((button) => {
  button.addEventListener("click", () => {
    state.activeFilter = button.dataset.filter;
    elements.filterButtons.forEach((item) => item.classList.toggle("active", item === button));
    renderTasks();
  });
});

bridge.getMeta().then((meta) => {
  setStatus(`${meta.mode} · v${meta.version}`);
});

renderTasks();
window.setInterval(tickSchedules, 1000);
